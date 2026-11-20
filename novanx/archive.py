from __future__ import annotations

import hashlib
import io
import re
import tarfile
import tomllib
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit


class ArchiveValidationError(ValueError):
    pass


PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
PACKAGE_VERSION = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
MAX_MEMBERS = 2000
MAX_UNPACKED_SIZE = 100 * 1024 * 1024
MAX_METADATA_SIZE = 128 * 1024
MAX_README_SIZE = 512 * 1024


def _safe_member_path(raw_path: str, *, is_directory: bool) -> PurePosixPath:
    normalized = raw_path.replace("\\", "/")
    if is_directory and normalized.endswith("/"):
        normalized = normalized[:-1]
    path = PurePosixPath(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or (len(normalized) >= 2 and normalized[1] == ":")
        or any(part in {"", ".."} for part in normalized.split("/"))
        or path.is_absolute()
    ):
        raise ArchiveValidationError("Archive contains an unsafe path.")
    return path


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        raise ArchiveValidationError("Package metadata or README is too large.")
    try:
        stream = archive.extractfile(member)
        if stream is None:
            raise ArchiveValidationError("Archive contains an unreadable file.")
        data = stream.read(limit + 1)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveValidationError("Archive contains a truncated or unreadable file.") from exc
    if len(data) > limit:
        raise ArchiveValidationError("Package metadata or README is too large.")
    if len(data) != member.size:
        raise ArchiveValidationError("Archive contains a truncated file.")
    return data


def validate_archive(
    filename: str,
    data: bytes,
    *,
    max_size: int,
) -> dict[str, Any]:
    if not filename.lower().endswith(".tar.nx"):
        raise ArchiveValidationError("Upload a Nexa package archive ending in .tar.nx.")
    if not data:
        raise ArchiveValidationError("The uploaded package archive is empty.")
    if len(data) > max_size:
        raise ArchiveValidationError("The uploaded package exceeds the size limit.")

    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveValidationError("The upload is not a valid .tar.nx archive.") from exc

    with archive:
        members = []
        try:
            for member in archive:
                if len(members) >= MAX_MEMBERS:
                    raise ArchiveValidationError("Archive has an invalid number of entries.")
                members.append(member)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise ArchiveValidationError("The upload is not a valid .tar.nx archive.") from exc
        if not members:
            raise ArchiveValidationError("Archive has an invalid number of entries.")

        paths: dict[str, tarfile.TarInfo] = {}
        unpacked_size = 0
        for member in members:
            path = _safe_member_path(member.name, is_directory=member.isdir())
            if not (member.isdir() or member.isfile()):
                raise ArchiveValidationError("Links and special files are not allowed.")
            if member.isfile():
                unpacked_size += member.size
                if unpacked_size > MAX_UNPACKED_SIZE:
                    raise ArchiveValidationError("Archive expands beyond the allowed size.")
                key = path.as_posix()
                if key in paths:
                    raise ArchiveValidationError("Archive contains duplicate file paths.")
                paths[key] = member

        metadata_candidates = [
            (path, member)
            for path, member in paths.items()
            if PurePosixPath(path).name == "nexa.toml"
            and len(PurePosixPath(path).parts) <= 2
        ]
        if len(metadata_candidates) != 1:
            raise ArchiveValidationError(
                "Package must contain exactly one root or top-level-folder nexa.toml."
            )

        _, metadata_member = metadata_candidates[0]
        try:
            manifest = tomllib.loads(_read_member(archive, metadata_member, MAX_METADATA_SIZE).decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ArchiveValidationError("The package nexa.toml is invalid.") from exc

        package = manifest.get("package")
        if not isinstance(package, dict):
            raise ArchiveValidationError("The package nexa.toml needs a [package] table.")

        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not PACKAGE_NAME.fullmatch(name):
            raise ArchiveValidationError("Package name must use lowercase letters, digits, '.', '_' or '-'.")
        if (
            not isinstance(version, str)
            or len(version) > 128
            or not PACKAGE_VERSION.fullmatch(version)
        ):
            raise ArchiveValidationError("Package version must use semantic versioning (for example 1.2.3).")

        description = package.get("description", "")
        license_name = package.get("license", "")
        requires_nexa = package.get("requires_nexa", package.get("nexa_version", ""))
        python_requires = package.get("python_requires", "")
        for field_name, value, limit in (
            ("description", description, 500),
            ("license", license_name, 100),
            ("requires_nexa", requires_nexa, 100),
            ("python_requires", python_requires, 100),
        ):
            if not isinstance(value, str) or len(value) > limit:
                raise ArchiveValidationError(f"Package {field_name} metadata is invalid.")

        dependencies = manifest.get("dependencies", package.get("dependencies", {}))
        if isinstance(dependencies, list):
            if any(not isinstance(item, str) or len(item) > 200 for item in dependencies):
                raise ArchiveValidationError("Package dependencies must be strings.")
        elif isinstance(dependencies, dict):
            if any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(key) > 100
                or len(value) > 200
                for key, value in dependencies.items()
            ):
                raise ArchiveValidationError("Package dependencies must map names to version constraints.")
        else:
            raise ArchiveValidationError("Package dependencies must be a table or an array of strings.")

        allowed_root = PurePosixPath(metadata_member.name).parent
        readme_member = None
        configured_readme = package.get("readme", "README.md")
        if isinstance(configured_readme, str):
            candidate = (allowed_root / configured_readme).as_posix()
            readme_member = paths.get(candidate)
        if readme_member is None:
            readme_member = next(
                (
                    member
                    for path, member in paths.items()
                    if PurePosixPath(path).parent == allowed_root
                    and PurePosixPath(path).name.lower() in {"readme.md", "readme.rst", "readme.txt"}
                ),
                None,
            )
        readme = ""
        if readme_member:
            try:
                readme = _read_member(archive, readme_member, MAX_README_SIZE).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ArchiveValidationError("The package README must be UTF-8 text.") from exc

        repository_url = package.get("repository_url", package.get("repository", ""))
        homepage_url = package.get("homepage_url", package.get("homepage", ""))
        for field_name, value in (("repository_url", repository_url), ("homepage_url", homepage_url)):
            if not isinstance(value, str) or len(value) > 2048:
                raise ArchiveValidationError(f"Package {field_name} metadata is invalid.")
            if value:
                try:
                    parsed = urlsplit(value)
                except ValueError as exc:
                    raise ArchiveValidationError(
                        f"Package {field_name} must be an HTTP(S) URL."
                    ) from exc
                if (
                    parsed.scheme not in {"https", "http"}
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                ):
                    raise ArchiveValidationError(f"Package {field_name} must be an HTTP(S) URL.")

        return {
            "name": name,
            "version": version,
            "description": description.strip(),
            "license": license_name.strip(),
            "requires_nexa": requires_nexa.strip(),
            "python_requires": python_requires.strip(),
            "dependencies": dependencies,
            "readme": readme,
            "repository_url": repository_url.strip(),
            "homepage_url": homepage_url.strip(),
            "checksum": hashlib.sha256(data).hexdigest(),
            "archive": data,
        }
