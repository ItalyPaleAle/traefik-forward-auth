#!/bin/bash

set -eu

# Create target directory
rm -rvf dist/ || true
mkdir -p dist

# Build the CSS using Tailwind
npx tailwindcss --minify --cwd src -i input.css -o ../dist/style.css

# Copy templates
cp -v src/*.tpl dist/
