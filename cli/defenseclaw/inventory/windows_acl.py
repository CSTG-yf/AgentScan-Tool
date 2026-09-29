# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed Windows owner and DACL checks for executable trust paths."""

from __future__ import annotations

import os


def trusted_path(path: str) -> bool:
    """Return whether *path* and its parents exclude untrusted writers.

    Trusted owners and write-capable ACEs are limited to the current user,
    LocalSystem, and built-in Administrators. The caller still requires an
    explicit trusted-prefix match before executing a user-installed binary.
    """
    if os.name != "nt" or not os.path.isabs(path):
        return False
    try:
        import win32api
        import win32con
        import win32security
        import ntsecuritycon
    except ImportError:
        return False

    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        current_user = win32security.GetTokenInformation(
            token, win32security.TokenUser
        )[0]
        administrators = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid, None
        )
        system = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid, None
        )
        trusted_installer = win32security.ConvertStringSidToSid(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )
        creator_owner = win32security.CreateWellKnownSid(
            win32security.WinCreatorOwnerSid, None
        )
        owner_rights = win32security.CreateWellKnownSid(
            win32security.WinCreatorOwnerRightsSid, None
        )
    except Exception:
        return False

    trusted_sids = {
        win32security.ConvertSidToStringSid(sid)
        for sid in (current_user, administrators, system, trusted_installer)
    }
    creator_owner_sid = win32security.ConvertSidToStringSid(creator_owner)
    owner_rights_sid = win32security.ConvertSidToStringSid(owner_rights)
    allow_types = {
        win32security.ACCESS_ALLOWED_ACE_TYPE,
        getattr(win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 5),
        getattr(win32security, "ACCESS_ALLOWED_CALLBACK_ACE_TYPE", 9),
        getattr(win32security, "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE", 11),
        getattr(win32security, "ACCESS_ALLOWED_COMPOUND_ACE_TYPE", 4),
    }
    structural_mask = (
        win32con.GENERIC_ALL
        | ntsecuritycon.DELETE
        | ntsecuritycon.WRITE_DAC
        | ntsecuritycon.WRITE_OWNER
        | ntsecuritycon.FILE_DELETE_CHILD
    )
    content_mask = (
        win32con.GENERIC_ALL
        | win32con.GENERIC_WRITE
        | ntsecuritycon.DELETE
        | ntsecuritycon.WRITE_DAC
        | ntsecuritycon.WRITE_OWNER
        | ntsecuritycon.FILE_WRITE_DATA
        | ntsecuritycon.FILE_APPEND_DATA
        | ntsecuritycon.FILE_WRITE_EA
        | ntsecuritycon.FILE_WRITE_ATTRIBUTES
        | ntsecuritycon.FILE_DELETE_CHILD
        | ntsecuritycon.FILE_ADD_FILE
    )

    # Check each parent: write access to a parent can replace a trusted child.
    current = os.path.normpath(path)
    seen: set[str] = set()
    depth = 0
    while current and current not in seen:
        seen.add(current)
        try:
            security = win32security.GetNamedSecurityInfo(
                current,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = security.GetSecurityDescriptorOwner()
            dacl = security.GetSecurityDescriptorDacl()
            if owner is None or dacl is None:
                return False
            if win32security.ConvertSidToStringSid(owner) not in trusted_sids:
                return False
            for index in range(dacl.GetAceCount()):
                ace = dacl.GetAce(index)
                (ace_type, ace_flags), mask = ace[0], int(ace[1])
                relevant_mask = content_mask if depth < 2 else structural_mask
                if ace_flags & win32con.INHERIT_ONLY_ACE:
                    continue
                if ace_type not in allow_types or not (mask & 0xFFFFFFFF) & relevant_mask:
                    continue
                if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
                    return False
                sid = win32security.ConvertSidToStringSid(ace[-1])
                if sid == owner_rights_sid:
                    continue
                if (ace_flags & win32con.INHERIT_ONLY_ACE) and sid == creator_owner_sid:
                    continue
                if sid not in trusted_sids:
                    return False
        except Exception:
            return False

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
        depth += 1
    return True


def directory_error(path: str) -> str | None:
    """Describe why a Windows directory DACL is unsafe to trust."""
    return None if trusted_path(path) else "directory owner or DACL is not trusted"
