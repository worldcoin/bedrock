#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load local env overrides if present
[[ -f "$PROJECT_ROOT/.env" ]] && source "$PROJECT_ROOT/.env"

WORLD_APP_PATH="${1:-$WORLD_APP_PATH}"

if [ -z "$WORLD_APP_PATH" ]; then
  echo "Error: Missing path to the WorldApp project. This is used to find and update the Package.swift that references bedrock-swift."
  echo "Usage: $0 /Path/To/WorldApp"
  echo "Or set WORLD_APP_PATH in .env"
  exit 1
fi

LOCAL_BUILD_PATH="$SCRIPT_DIR/local_build/bedrock-swift"

echo "Building the Bedrock Swift package..."
bash "$SCRIPT_DIR/local_swift.sh"

echo "Finding Package.swift files that reference bedrock-swift..."
PACKAGE_FILES=$(grep -rl "worldcoin/bedrock-swift" "$WORLD_APP_PATH" --include="Package.swift" --exclude-dir=".build" --exclude-dir=".claude" || true)

if [ -z "$PACKAGE_FILES" ]; then
  echo "Warning: No Package.swift found referencing worldcoin/bedrock-swift in $WORLD_APP_PATH"
  exit 1
fi

while IFS= read -r pkg_file; do
  echo "Patching $pkg_file..."
  sed -i '' "s|\.package(url: \"https://github.com/worldcoin/bedrock-swift\", exact: \"[^\"]*\")|.package(path: \"$LOCAL_BUILD_PATH\")|" "$pkg_file"
done <<< "$PACKAGE_FILES"

echo "Done! In Xcode, make sure package resolution succeeds (via the Issue Navigator). You can get opaque build failures if the package isn't where the app expects it to be."
