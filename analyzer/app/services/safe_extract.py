from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from app.core.config import MAX_FILES, MAX_MEMBER_BYTES, MAX_UNPACKED_BYTES


class UnsafeArchive(ValueError):
    pass


def extract_archive(archive: Path, destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    files: list[Path] = []
    total = 0
    try:
        with zipfile.ZipFile(archive) as zf:
            members = zf.infolist()
            if len(members) > MAX_FILES:
                raise UnsafeArchive("Archive contains too many entries")
            for item in members:
                member = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                if member.is_absolute() or ".." in member.parts or "\\" in item.filename or ":" in item.filename or not member.parts:
                    raise UnsafeArchive("Archive contains an unsafe path")
                if stat.S_ISLNK(mode):
                    raise UnsafeArchive("Archive contains a symbolic link")
                if item.is_dir():
                    continue
                if item.file_size > MAX_MEMBER_BYTES:
                    raise UnsafeArchive("Archive entry exceeds the size limit")
                if item.file_size and (item.compress_size == 0 or item.file_size / item.compress_size > 100):
                    raise UnsafeArchive("Archive entry exceeds the compression-ratio limit")
                total += item.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise UnsafeArchive("Archive exceeds the expanded size limit")
                target = (root / Path(*member.parts)).resolve()
                if not target.is_relative_to(root):
                    raise UnsafeArchive("Archive path escapes extraction directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(item) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                files.append(target)
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive("File is not a valid ZIP archive") from exc
    return files
