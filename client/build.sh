#!/bin/sh

set -euo pipefail

# Create target directory
mkdir -p dist

# Clean compiled files
rm -rvf dist/*.tpl || true
rm -rvf dist/style.css || true

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i input.css -o ../dist/style.css

# Copy templates
cp -v src/*.tpl dist/
