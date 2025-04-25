#!/bin/sh

set -euo pipefail

# Create target directory
rm -rvf dist/
mkdir -p dist

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i input.css -o ../dist/style.css
