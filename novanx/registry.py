from __future__ import annotations

import logging
import uuid
from typing import Any
from urllib.parse import quote, urlencode

from .archive import validate_archive
from .config import Settings
from .storage import SupabaseStorage
from .supabase import SupabaseClient, SupabaseError, first_row


def _filter_url(table: str, **filters: str) -> str:
    return f"{table}?{urlencode(filters)}"


def _in_filter(values: list[str]) -> str:
    return "in.(" + ",".join(values) + ")"


class Registry:
    def __init__(
        self,
        settings: Settings,
        *,
        privileged: bool = False,
        user_access_token: str | None = None,
    ) -> None:
        self.settings = settings
        self.db = SupabaseClient(
            settings,
            privileged=privileged,
            user_access_token=user_access_token,
        )
        self._storage: SupabaseStorage | None = None

    @property
    def storage(self) -> SupabaseStorage:
        if self._storage is None:
            self._storage = SupabaseStorage(self.settings)
        return self._storage

    def _package_rows(self, filter_value: str | None = None) -> list[dict[str, Any]]:
        query = {"select": "*", "order": "updated_at.desc", "limit": "500"}
        if filter_value:
            query.update({"id": filter_value})
        rows, _ = self.db.rest(f"packages?{urlencode(query)}")
        return rows if isinstance(rows, list) else []

    def _enrich(
        self,
        packages: list[dict[str, Any]],
        *,
        include_maintainers: bool = False,
    ) -> list[dict[str, Any]]:
        if not packages:
            return []
        ids = [str(row["id"]) for row in packages if row.get("id")]
        owner_ids = list({str(row["owner_id"]) for row in packages if row.get("owner_id")})
        if not ids:
            return packages
        versions, _ = self.db.rest(
            _filter_url(
                "package_versions",
                select="id,package_id,version,created_at,checksum,license,requires_nexa,"
                "python_requires,dependencies,readme,archive_path",
                package_id=_in_filter(ids),
                order="created_at.desc",
                limit="2000",
            )
        )
        profiles: list[dict[str, Any]] = []
        if owner_ids:
            profiles, _ = self.db.rest(
                _filter_url("profiles", select="id,username", id=_in_filter(owner_ids))
            )
        maintainer_rows: list[dict[str, Any]] = []
        if include_maintainers:
            maintainer_rows, _ = self.db.rest(
                _filter_url(
                    "package_maintainers",
                    select="package_id,user_id,permission",
                    package_id=_in_filter(ids),
                )
            )
            maintainer_ids = list(
                {
                    str(row["user_id"])
                    for row in maintainer_rows or []
                    if isinstance(row, dict) and row.get("user_id")
                }
            )
            missing_profile_ids = [item for item in maintainer_ids if item not in owner_ids]
            if missing_profile_ids:
                extra_profiles, _ = self.db.rest(
                    _filter_url("profiles", select="id,username", id=_in_filter(missing_profile_ids))
                )
                profiles.extend(extra_profiles or [])
        owners = {
            str(profile["id"]): profile.get("username", "Nexa developer")
            for profile in profiles or []
            if isinstance(profile, dict) and profile.get("id")
        }
        latest: dict[str, dict[str, Any]] = {}
        all_versions: dict[str, list[dict[str, Any]]] = {}
        for version in versions or []:
            if not isinstance(version, dict):
                continue
            package_id = str(version.get("package_id", ""))
            all_versions.setdefault(package_id, []).append(version)
            latest.setdefault(package_id, version)

        for package in packages:
            package_id = str(package.get("id", ""))
            package["author"] = owners.get(str(package.get("owner_id")), "Nexa developer")
            package["latest"] = latest.get(package_id)
            package["versions"] = all_versions.get(package_id, [])
            package["download_count"] = int(package.get("download_count") or 0)
            if include_maintainers:
                package["maintainers"] = [
                    {
                        "user_id": row["user_id"],
                        "username": owners.get(str(row["user_id"]), "Nexa developer"),
                        "permission": row.get("permission", "publish"),
                    }
                    for row in maintainer_rows or []
                    if isinstance(row, dict) and str(row.get("package_id")) == package_id
                ]
        return packages

    def catalog(
        self,
        *,
        query: str = "",
        sort: str = "relevance",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        rows, _ = self.db.rest(
            "rpc/novanx_search_packages",
            method="POST",
            payload={
                "search_text": query.strip()[:100],
                "sort_order": sort,
                "result_limit": max(1, min(limit, 500)),
            },
        )
        return self._enrich(rows if isinstance(rows, list) else [])

    def stats(self) -> dict[str, int]:
        data, _ = self.db.rest("rpc/novanx_registry_stats", method="POST", payload={})
        row = first_row(data) or {}
        return {
            "packages": int(row.get("package_count") or 0),
            "downloads": int(row.get("download_count") or 0),
            "authors": int(row.get("author_count") or 0),
        }

    def package(self, name: str) -> dict[str, Any] | None:
        rows, _ = self.db.rest(
            _filter_url("packages", select="*", name=f"eq.{name}", limit="1")
        )
        rows = rows if isinstance(rows, list) else []
        return self._enrich(rows)[0] if rows else None

    def packages_for_user(self, user_id: str) -> list[dict[str, Any]]:
        rows, _ = self.db.rest(
            _filter_url("packages", select="*", owner_id=f"eq.{user_id}", order="updated_at.desc")
        )
        packages = rows if isinstance(rows, list) else []
        maintainers, _ = self.db.rest(
            _filter_url("package_maintainers", select="package_id", user_id=f"eq.{user_id}")
        )
        package_ids = list(
            {
                str(row["package_id"])
                for row in (maintainers or [])
                if isinstance(row, dict) and row.get("package_id")
            }
        )
        owned_ids = {str(row.get("id")) for row in packages}
        additional_ids = [item for item in package_ids if item not in owned_ids]
        if additional_ids:
            additional = self._package_rows(_in_filter(additional_ids))
            packages.extend(additional)
        return self._enrich(packages, include_maintainers=True)

    def can(self, package: dict[str, Any], user_id: str, permission: str) -> bool:
        if str(package.get("owner_id")) == user_id:
            return True
        rows, _ = self.db.rest(
            _filter_url(
                "package_maintainers",
                select="permission",
                package_id=f"eq.{package['id']}",
                user_id=f"eq.{user_id}",
            )
        )
        allowed = {"read": {"read", "publish", "manage"}, "publish": {"publish", "manage"},
                   "manage": {"manage"}}
        return any(
            isinstance(row, dict) and row.get("permission") in allowed.get(permission, set())
            for row in rows or []
        )

    def publish(
        self,
        filename: str,
        data: bytes,
        owner_id: str,
        *,
        expected_name: str | None = None,
        expected_version: str | None = None,
    ) -> dict[str, Any]:
        metadata = validate_archive(filename, data, max_size=self.settings.max_archive_size)
        name = metadata["name"]
        version = metadata["version"]
        if expected_name and expected_name != name:
            raise ValueError("The archive package name does not match the requested package.")
        if expected_version and expected_version != version:
            raise ValueError("The archive version does not match the requested version.")

        package = self.package(name)
        is_new = package is None
        if is_new:
            package_body = {
                "name": name,
                "description": metadata["description"],
                "owner_id": owner_id,
                "repository_url": metadata["repository_url"],
                "homepage_url": metadata["homepage_url"],
                "is_deprecated": False,
                "download_count": 0,
            }
            inserted, _ = self.db.rest(
                "packages",
                method="POST",
                payload=package_body,
                headers={"Prefer": "return=representation"},
            )
            package = first_row(inserted)
            if not package:
                raise SupabaseError("Supabase did not return the created package record.")
        elif str(package.get("owner_id")) != owner_id and not self.can(package, owner_id, "publish"):
            raise PermissionError("You do not have permission to publish versions of this package.")

        existing, _ = self.db.rest(
            _filter_url(
                "package_versions",
                select="id",
                package_id=f"eq.{package['id']}",
                version=f"eq.{version}",
            )
        )
        if existing:
            if is_new:
                self.db.rest(f"packages?id=eq.{package['id']}", method="DELETE")
            raise SupabaseError("That package version already exists.", 409)

        archive_path = f"{name}/{version}/{metadata['checksum']}-{uuid.uuid4().hex}.tar.nx"
        uploaded = False
        version_id: str | None = None
        try:
            self.storage.upload(self.settings.storage_bucket, archive_path, data)
            uploaded = True
            version_row, _ = self.db.rest(
                "package_versions",
                method="POST",
                payload={
                    "package_id": package["id"],
                    "version": version,
                    "archive_path": archive_path,
                    "checksum": metadata["checksum"],
                    "readme": metadata["readme"],
                    "license": metadata["license"],
                    "requires_nexa": metadata["requires_nexa"],
                    "python_requires": metadata["python_requires"],
                    "dependencies": metadata["dependencies"],
                },
                headers={"Prefer": "return=representation"},
            )
            created_version = first_row(version_row)
            if not created_version or not created_version.get("id"):
                raise SupabaseError("Supabase did not return the created package version.")
            version_id = str(created_version["id"])
            self.db.rest(
                f"packages?id=eq.{package['id']}",
                method="PATCH",
                payload={
                    "description": metadata["description"] or package.get("description", ""),
                    "repository_url": metadata["repository_url"] or package.get("repository_url", ""),
                    "homepage_url": metadata["homepage_url"] or package.get("homepage_url", ""),
                },
            )
        except Exception:
            if version_id:
                try:
                    self.db.rest(f"package_versions?id=eq.{version_id}", method="DELETE")
                except SupabaseError:
                    logging.exception("Could not remove package version after a failed publish.")
            if uploaded:
                try:
                    self.delete_archive(archive_path)
                except SupabaseError:
                    logging.exception("Could not remove package archive after a failed publish.")
            if is_new:
                try:
                    self.db.rest(f"packages?id=eq.{package['id']}", method="DELETE")
                except SupabaseError:
                    logging.exception("Could not remove package record after a failed publish.")
            raise

        return {
            "name": name,
            "version": version,
            "checksum": metadata["checksum"],
            "archive_path": archive_path,
        }

    def delete_archive(self, archive_path: str) -> None:
        self.storage.delete(self.settings.storage_bucket, archive_path)

    def download(self, package: dict[str, Any], version: dict[str, Any]) -> bytes:
        archive_path = str(version["archive_path"])
        data = self.storage.download(self.settings.storage_bucket, archive_path)
        self.db.rest(
            "package_downloads",
            method="POST",
            payload={"package_id": package["id"], "version_id": version["id"]},
        )
        return data


def public_version(version: dict[str, Any], package_name: str, base_url: str = "") -> dict[str, Any]:
    relative_url = (
        f"/api/packages/{quote(package_name, safe='')}/download?"
        f"{urlencode({'version': version['version']})}"
    )
    download_url = f"{base_url}{relative_url}" if base_url else relative_url
    return {
        "version": version.get("version"),
        "checksum": version.get("checksum"),
        "download_url": download_url,
        "download_link": download_url,
        "archive_format": ".tar.nx",
        "license": version.get("license"),
        "requires_nexa": version.get("requires_nexa"),
        "python_requires": version.get("python_requires"),
        "dependencies": version.get("dependencies"),
        "created_at": version.get("created_at"),
    }


def json_package(package: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    versions = [
        public_version(version, str(package["name"]), base_url)
        for version in package.get("versions", [])
    ]
    latest = package.get("latest")
    return {
        "name": package.get("name"),
        "description": package.get("description", ""),
        "author": package.get("author", ""),
        "latest_version": latest.get("version") if latest else None,
        "download_url": public_version(latest, package["name"], base_url)["download_url"]
        if latest
        else None,
        "download_link": public_version(latest, package["name"], base_url)["download_link"]
        if latest
        else None,
        "versions": versions,
        "downloads": package.get("download_count", 0),
        "repository_url": package.get("repository_url", ""),
        "homepage_url": package.get("homepage_url", ""),
        "is_deprecated": package.get("is_deprecated", False),
        "created_at": package.get("created_at"),
        "updated_at": package.get("updated_at"),
    }
