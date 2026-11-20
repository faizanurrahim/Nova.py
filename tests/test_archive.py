from __future__ import annotations

import io
import tarfile
import unittest

from novanx.archive import ArchiveValidationError, validate_archive


MANIFEST = b"""[package]
name = "nexaextra"
version = "1.2.0"
description = "Useful extras"
requires_nexa = ">=0.5.2"
python_requires = ">=3.11"

[dependencies]
httpx = ">=0.27"
"""


def build_archive(entries: list[tuple[str, bytes | None, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "../outside"
                archive.addfile(info)
            else:
                body = data or b""
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


class ValidateArchiveTests(unittest.TestCase):
    def test_reads_top_level_package_manifest_and_readme(self) -> None:
        payload = build_archive(
            [
                ("nexaextra/", None, "directory"),
                ("nexaextra/nexa.toml", MANIFEST, "file"),
                ("nexaextra/README.md", b"# Nexa extra\n", "file"),
            ]
        )

        result = validate_archive("nexaextra.tar.nx", payload, max_size=1024 * 1024)

        self.assertEqual(result["name"], "nexaextra")
        self.assertEqual(result["version"], "1.2.0")
        self.assertEqual(result["readme"], "# Nexa extra\n")
        self.assertEqual(len(result["checksum"]), 64)

    def test_rejects_traversal_and_link_members(self) -> None:
        traversal = build_archive([("../outside.txt", b"no", "file")])
        link = build_archive(
            [
                ("nexa.toml", MANIFEST, "file"),
                ("shortcut", None, "symlink"),
            ]
        )

        with self.assertRaises(ArchiveValidationError):
            validate_archive("bad.tar.nx", traversal, max_size=1024 * 1024)
        with self.assertRaises(ArchiveValidationError):
            validate_archive("bad.tar.nx", link, max_size=1024 * 1024)

    def test_rejects_bad_extension_oversize_and_invalid_manifest(self) -> None:
        payload = build_archive([("nexa.toml", MANIFEST, "file")])
        bad_manifest = build_archive([("nexa.toml", b"[package\nname = 'bad'", "file")])

        with self.assertRaises(ArchiveValidationError):
            validate_archive("nexaextra.tar", payload, max_size=1024 * 1024)
        with self.assertRaises(ArchiveValidationError):
            validate_archive("nexaextra.tar.nx", payload, max_size=1)
        with self.assertRaises(ArchiveValidationError):
            validate_archive("nexaextra.tar.nx", bad_manifest, max_size=1024 * 1024)


if __name__ == "__main__":
    unittest.main()
