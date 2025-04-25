#!/bin/sh

set -euo pipefail

# Build the CSS using Tailwind
rm output.css || true
npx tailwindcss --minify -i input.css -o output.css
