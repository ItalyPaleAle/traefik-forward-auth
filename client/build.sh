#!/bin/sh

set -euo pipefail

# Create target directory
rm -rvf dist/
mkdir -p dist

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i input.css -o ../dist/style.css

# Copy templates
cp -v src/*.tpl dist/

# Copy icons and images
cp -rv src/img dist
cp -rv src/icons dist
