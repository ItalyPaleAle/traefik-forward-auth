#!/bin/sh

set -euo pipefail

# Build the CSS using Tailwind
rm output.css || true
npx tailwindcss -i input.css -o output.css
