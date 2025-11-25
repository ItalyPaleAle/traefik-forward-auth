#!/usr/bin/env node

const fs = require('fs')
const path = require('path')

const iconsDir = path.join(__dirname, 'icons')
const outputFile = path.join(__dirname, 'dist', 'icons.js')
const templateFile = path.join(__dirname, 'src', 'icons.js.tpl')

// Read all SVG files from the icons directory
const iconFiles = fs.readdirSync(iconsDir).filter(file => file.endsWith('.svg'))

// Build the icons object
const icons = {}
iconFiles.forEach(file => {
    const iconName = path.basename(file, '.svg')
    const svgContent = fs.readFileSync(path.join(iconsDir, file), 'utf8')
    // Remove comments and minify the SVG
    const minified = svgContent
        .replace(/<!--[\s\S]*?-->/g, '') // Remove XML/HTML comments
        .replace(/\s+/g, ' ') // Collapse whitespace
        .trim()
    icons[iconName] = minified
})

// Read the template file
const template = fs.readFileSync(templateFile, 'utf8')

// Generate the JavaScript output by replacing the placeholder
const jsOutput = template.replace('{/*ICONS_DATA*/}', JSON.stringify(icons, null, 4))

// Write the output file
fs.writeFileSync(outputFile, jsOutput, 'utf8')

console.log(`✓ Generated ${outputFile} with ${iconFiles.length} icons`)
