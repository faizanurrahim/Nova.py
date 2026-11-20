from __future__ import annotations

from urllib.parse import quote

from .config import Settings
from .supabase import SupabaseClient, SupabaseError


class SupabaseStorage:
    def __init__(self, settings: Settings) -> None:
        self.client = SupabaseClient(settings, privileged=True)

    def upload(self, bucket: str, path: str, data: bytes) -> None:
        object_path = quote(f"{bucket}/{path}", safe="/")
        self.client.request(
            f"storage/v1/object/{object_path}",
            method="POST",
            raw_body=data,
            content_type="application/octet-stream",
            headers={"Accept": "*/*"},
        )

    def delete(self, bucket: str, path: str) -> None:
        self.client.request(
            f"storage/v1/object/{quote(bucket, safe='')}",
            method="DELETE",
            payload={"prefixes": [path]},
            headers={"Accept": "*/*"},
        )

    def download(self, bucket: str, path: str) -> bytes:
        object_path = quote(f"{bucket}/{path}", safe="/")
        data, _ = self.client.request(
            f"storage/v1/object/{object_path}",
            headers={"Accept": "*/*"},
        )
        if not isinstance(data, bytes):
            raise SupabaseError("Package archive storage returned an invalid response.")
        return data
