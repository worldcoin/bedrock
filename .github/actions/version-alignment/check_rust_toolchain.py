#!/usr/bin/env python3
"""
Checks that the Rust toolchain channel in rust-toolchain.toml matches the
expected channel defined in the RUST_TOOLCHAIN_CHANNEL CI variable.
"""

import os
import re
import sys
import unittest


def find_toolchain_channel(content: str):
    return re.search(r'^channel\s*=\s*"([^"]+)"', content, re.MULTILINE)


def get_rust_toolchain_channel(toolchain_toml_path: str) -> str:
    with open(toolchain_toml_path) as f:
        content = f.read()

    match = find_toolchain_channel(content)
    if not match:
        print("::error::Could not find channel in rust-toolchain.toml")
        sys.exit(1)

    return match.group(1)


def main():
    expected_channel = os.environ.get("RUST_TOOLCHAIN_CHANNEL")
    if not expected_channel:
        print("::error::RUST_TOOLCHAIN_CHANNEL environment variable is not set")
        sys.exit(1)

    workspace = os.environ.get(
        "GITHUB_WORKSPACE",
        os.path.join(os.path.dirname(__file__), "..", "..", ".."),
    )

    toolchain_toml = os.path.join(workspace, "rust-toolchain.toml")
    actual_channel = get_rust_toolchain_channel(toolchain_toml)

    if actual_channel != expected_channel:
        print(
            f"::error::Rust toolchain channel mismatch!\n"
            f"  rust-toolchain.toml: {actual_channel}\n"
            f"  CI variable:         {expected_channel}"
        )
        sys.exit(1)

    print(f"::notice::Rust toolchain channel '{actual_channel}' matches CI variable")


# Tests
class TestFindToolchainChannel(unittest.TestCase):
    def test_finds_channel(self):
        toolchain_toml = """
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
"""
        match = find_toolchain_channel(toolchain_toml)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "stable")

    def test_finds_nightly_channel(self):
        toolchain_toml = """
[toolchain]
channel = "nightly-2024-01-01"
"""
        match = find_toolchain_channel(toolchain_toml)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "nightly-2024-01-01")


if __name__ == "__main__":
    # To test, run the following at the project root
    # python3 .github/actions/version-alignment/check_rust_toolchain.py test
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("test mode")

        sys.argv.pop(1)
        unittest.main()
    else:
        main()
