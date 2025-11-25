#!/bin/bash

set -eu

# Create target directory
rm -rvf dist/ || true
mkdir -p dist

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i input.css -o ../dist/style.css

# Copy templates
cp -v src/*.html.tpl dist/

# Remove whitespaces from the start of lines in the template files
# This is a simplistic minification
for f in dist/*.html.tpl; do
    sed -i.bak 's/^[[:space:]]*//g' "$f"
    rm "$f.bak"
done

# Build icons
node build-icons.js

# Minify the icons.js file
npx terser dist/icons.js -o dist/icons.js --compress --mangle
