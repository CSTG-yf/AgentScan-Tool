"""Windows owner/DACL contract for trusted Agent discovery binaries."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ACL contract")


def _private_fixture_dir() -> Path:
    root = Path(os.environ["USERPROFILE"]) / f".defenseclaw-acl-test-{uuid.uuid4().hex}"
    root.mkdir()
    return root


def _grant_everyone_write(path: Path) -> None:
    import win32security

    security = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = security.GetSecurityDescriptorDacl()
    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)
    dacl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION_DS,
        0,
        0x40000000,  # GENERIC_WRITE
        everyone,
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def test_user_profile_acl_is_accepted_as_private_trusted_root():
    from defenseclaw.inventory.windows_acl import trusted_path

    assert trusted_path(os.environ["USERPROFILE"])


def test_untrusted_writer_ace_rejects_binary_even_under_trusted_root():
    from defenseclaw.inventory.windows_acl import trusted_path

    root = _private_fixture_dir()
    try:
        binary = root / "codex.exe"
        binary.write_bytes(b"fixture")
        assert trusted_path(str(binary))

        _grant_everyone_write(binary)
        assert not trusted_path(str(binary))
    finally:
        shutil.rmtree(root)


def test_untrusted_writer_ace_on_parent_directory_rejects_child_binary():
    from defenseclaw.inventory.windows_acl import trusted_path

    root = _private_fixture_dir()
    try:
        binary = root / "codex.exe"
        binary.write_bytes(b"fixture")
        _grant_everyone_write(root)
        assert not trusted_path(str(binary))
    finally:
        shutil.rmtree(root)
