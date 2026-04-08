#!/usr/bin/env python3
"""
Checks that the uniffi version in Cargo.toml matches the expected version
passed as a CLI argument.
"""

import argparse
import os
import re
import sys
import unittest
import urllib.request
from typing import Optional

XMTP_CARGO_TOML_URL = (
    "https://raw.githubusercontent.com/xmtp/libxmtp/main/bindings/mobile/Cargo.toml"
)


def find_uniffi_version(content: str) -> Optional[str]:
    # Use alternation to keep the two forms mutually exclusive, avoiding
    # false matches on other quoted values inside an inline table (e.g. git = "…"):
    #   plain string:   uniffi = "0.31.0"
    #   inline table:   uniffi = { version = "0.31.0", ... }
    match = re.search(
        r'uniffi\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")',
        content,
    )
    if not match:
        return None
    return match.group(1) or match.group(2)


def get_cargo_uniffi_version(cargo_toml_path: str) -> Optional[str]:
    with open(cargo_toml_path) as f:
        content = f.read()

    return find_uniffi_version(content)


def get_extern_lib_uniffi_version() -> Optional[str]:
    """
    Checks the external repo. This will soft-fail.
    """
    try:
        with urllib.request.urlopen(XMTP_CARGO_TOML_URL, timeout=60) as response:
            content = response.read().decode("utf-8")

        version = find_uniffi_version(content)
        if not version:
            print("::warning::Could not find uniffi version in libxmtp")
            return None

        return version
    except Exception as err:
        print(
            f"::warning::Couldn't retrieve version from remote repository, error: {err}"
        )
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--expected-version",
        required=True,
        help="Expected uniffi version (from UNIFFI_VERSION CI variable)",
    )
    args = parser.parse_args()

    workspace = os.environ.get(
        "GITHUB_WORKSPACE",
        os.path.join(os.path.dirname(__file__), "..", "..", ".."),
    )

    cargo_toml = os.path.join(workspace, "Cargo.toml")
    actual_version = get_cargo_uniffi_version(cargo_toml)

    if actual_version is None:
        print(
            "::notice::uniffi is not a dependency in Cargo.toml, skipping version check"
        )
        return

    if actual_version != args.expected_version:
        print(
            f"::error::uniffi version mismatch!\n"
            f"  Cargo.toml:       {actual_version}\n"
            f"  CI variable:      {args.expected_version}"
        )
        sys.exit(1)

    print(f"::notice::uniffi version {actual_version} matches CI variable")

    # External lib check failure doesn't fail the test but it raises warning
    xmtp_version = get_extern_lib_uniffi_version()
    if xmtp_version is not None and xmtp_version != args.expected_version:
        print(
            f"::warning::uniffi version mismatch with libxmtp, "
            f"expected version={args.expected_version}, libxmtp={xmtp_version}"
        )


# Tests
class TestFindUniffiVersion(unittest.TestCase):
    def test_finds_version_inline_table(self):
        cargo_toml = """
[workspace.dependencies]
uniffi = { version = "0.31.0", features = ["tokio"] }
"""
        self.assertEqual(find_uniffi_version(cargo_toml), "0.31.0")

    def test_finds_version_plain_string(self):
        cargo_toml = """
[workspace.dependencies]
uniffi = "0.31.0"
"""
        self.assertEqual(find_uniffi_version(cargo_toml), "0.31.0")

    def test_ignores_inline_table_without_version(self):
        cargo_toml = """
[workspace.dependencies]
uniffi = { git = "https://github.com/mozilla/uniffi-rs" }
"""
        self.assertIsNone(find_uniffi_version(cargo_toml))

    def test_get_extern_lib(self):
        xmtp_version = get_extern_lib_uniffi_version()

        print(f"retrieved xmtp_version={xmtp_version}")
        self.assertIsNotNone(xmtp_version)


if __name__ == "__main__":
    # To test, run the following at the project root
    # python3 .github/actions/version-alignment/check_uniffi_version.py test

    # To run normally:
    # python3 .github/actions/version-alignment/check_uniffi_version.py \
    #   --expected-version <version>
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("test mode")

        sys.argv.pop(1)
        unittest.main()
    else:
        main()
