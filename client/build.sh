#!/bin/bash

set -eu

# Create target directory
rm -rvf dist/ || true
mkdir -p dist

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i style.css -o ../dist/style.css

# Minify the icons.js file
npx terser src/icons.js -o dist/icons.js --compress --mangle

# Hash a file and print the first 12 hex chars
hash_file() {
    openssl dgst -sha256 "$1" | awk '{print $NF}' | cut -c1-12
}

# Hash + rename style.css and pre-compress with gzip
# icons.js is left at its plain name; its content depends on the ?include query (which already busts caches), and it is gzipped on the fly at runtime
STYLE_HASH=$(hash_file dist/style.css)
STYLE_NAME="style.${STYLE_HASH}.css"
mv dist/style.css "dist/${STYLE_NAME}"
gzip -9 -c "dist/${STYLE_NAME}" > "dist/${STYLE_NAME}.gz"

# Write the asset manifest consumed by the server at startup
cat > dist/manifest.json <<EOF
{
  "style": "${STYLE_NAME}"
}
EOF

# Copy templates
cp -v src/*.html.tpl dist/

# Remove whitespaces from the start of lines in the template files
# This is a simplistic minification
for f in dist/*.html.tpl; do
    sed -i.bak 's/^[[:space:]]*//g' "$f"
    rm "$f.bak"
done
