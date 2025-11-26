(() => {
    'use strict'

    // Icon data
    const icons = process.env.ICONS_DATA

    // Initialize icons when DOM is ready
    function initIcons() {
        const elements = document.querySelectorAll('[data-svg-icon]')
        elements.forEach(function(element) {
            const iconName = element.getAttribute('data-svg-icon')
            // Insert the SVG at the start of the element, replacing the default empty SVG (required to ensure alignment and avoid content shift)
            if (icons[iconName]) {
                const tpl = document.createElement('template')
                tpl.innerHTML = icons[iconName]
                element.replaceChild(tpl.content.firstElementChild, element.firstElementChild)
            }
        })
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initIcons)
    } else {
        initIcons()
    }
})()
