'use strict'

(function() {

    // Icon data
    const icons = {/*ICONS_DATA*/}

    // Initialize icons when DOM is ready
    function initIcons() {
        const elements = document.querySelectorAll('[data-svg-icon]')
        elements.forEach(function(element) {
            const iconName = element.getAttribute('data-svg-icon')
            if (icons[iconName]) {
                // Insert the SVG at the start of the element
                element.insertAdjacentHTML('afterbegin', icons[iconName])
            } else {
                console.warn('Icon not found: ' + iconName)
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
