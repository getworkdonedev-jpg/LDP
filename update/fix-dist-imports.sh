#!/usr/bin/env bash
# LDP — Fix dist/ import extensions
# ===================================
# Problem: tsc compiles .ts → .js but does NOT rewrite import paths.
# If source files use `import ... from "./engine.js"` that is fine.
# But several dist/ files were found importing `"./engine.ts"` — this
# breaks in any real Node.js runtime (only works with tsx in dev mode).
#
# This script patches all .js files in dist/ to ensure every local
# import uses .js extension, never .ts.
#
# Usage:
#   bash fix-dist-imports.sh [dist-dir]
#   Default dist-dir: ./dist

DIST=${1:-./dist}

if [ ! -d "$DIST" ]; then
  echo "❌ dist dir not found: $DIST"
  exit 1
fi

echo "Fixing imports in $DIST..."
FIXED=0

for f in "$DIST"/**/*.js "$DIST"/*.js; do
  [ -f "$f" ] || continue

  if grep -q "from ['\"]\..*\.ts['\"]" "$f" 2>/dev/null; then
    # Replace all .ts extensions in import/export statements with .js
    sed -i.bak \
      "s/from '\(\.\.\/\?\.*[^']*\)\.ts'/from '\1.js'/g" "$f"
    sed -i.bak \
      's/from "\(\.\.\/\?\.*[^"]*\)\.ts"/from "\1.js"/g' "$f"
    sed -i.bak \
      "s/import('\(\.\.\/\?\.*[^']*\)\.ts')/import('\1.js')/g" "$f"
    sed -i.bak \
      's/import("\(\.\.\/\?\.*[^"]*\)\.ts")/import("\1.js")/g' "$f"
    rm -f "${f}.bak"
    echo "  ✓ fixed: $f"
    FIXED=$((FIXED + 1))
  fi
done

echo ""
echo "Done. Fixed $FIXED file(s)."
echo ""
echo "To verify no .ts imports remain:"
echo "  grep -r \"from '.*\\.ts'\" $DIST"
echo "  grep -r 'from \".*\\.ts\"' $DIST"
