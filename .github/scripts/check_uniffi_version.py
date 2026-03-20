#!/usr/bin/env python3
"""
Checks that the uniffi version in Cargo.toml matches the expected version
defined in the UNIFFI_VERSION CI variable.
"""

import os
import re
import sys
import unittest
import urllib.request
from typing import Optional

XMTP_CARGO_TOML_URL = (
    "https://raw.githubusercontent.com/xmtp/libxmtp/main/bindings/mobile/Cargo.toml"
)


def find_uniffi_version(content: str):
    return re.search(r'uniffi\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', content)


def get_cargo_uniffi_version(cargo_toml_path: str) -> str:
    with open(cargo_toml_path) as f:
        content = f.read()

    match = find_uniffi_version(content)
    if not match:
        print("::error::Could not find uniffi version in Cargo.toml")
        sys.exit(1)

    return match.group(1)


def get_extern_lib_uniffi_version() -> Optional[str]:
    """
    Checks the external repo. This will soft-fail.
    """
    try:
        with urllib.request.urlopen(XMTP_CARGO_TOML_URL, timeout=60) as response:
            content = response.read().decode("utf-8")

        match = find_uniffi_version(content)
        if not match:
            print("::warning::Could not find uniffi version in libxmtp")
            return None

        return match.group(1)
    except Exception as err:
        print(
            f"::warning::Couldn't retrieve version from remote repository, error: {err}"
        )
        return None


def main():
    expected_version = os.environ.get("UNIFFI_VERSION")
    if not expected_version:
        print("::error::UNIFFI_VERSION environment variable is not set")
        sys.exit(1)

    curr_file_path = os.path.dirname(__file__)

    cargo_toml = os.path.join(curr_file_path, "..", "..", "Cargo.toml")
    actual_version = get_cargo_uniffi_version(cargo_toml)

    if actual_version != expected_version:
        print(
            f"::error::uniffi version mismatch!\n"
            f"  Cargo.toml:       {actual_version}\n"
            f"  CI variable:      {expected_version}"
        )
        sys.exit(1)

    print(f"::notice::uniffi version {actual_version} matches CI variable")

    # External lib check failure doesn't fail the test but it raises warning
    xmtp_version = get_extern_lib_uniffi_version()
    if xmtp_version is not None and xmtp_version != expected_version:
        print(
            f"::warning::uniffi version mismatch with libxmtp, "
            f"expected version={expected_version}, libxmtp={xmtp_version}"
        )


# Tests
class TestFindUniffiVersion(unittest.TestCase):
    def test_finds_version(self):
        cargo_toml = """
[workspace.dependencies]
uniffi = { version = "0.31.0", features = ["tokio"] }
"""
        match = find_uniffi_version(cargo_toml)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "0.31.0")

    def test_get_extern_lib(self):
        xmtp_version = get_extern_lib_uniffi_version()

        print(f"retrieved xmtp_version={xmtp_version}")
        self.assertIsNotNone(xmtp_version)


if __name__ == "__main__":
    # To test, run the following at the project root
    # python3 .github/scripts/check_uniffi_version.py test
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("test mode")

        sys.argv.pop(1)
        unittest.main()
    else:
        main()
