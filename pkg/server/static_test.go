package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinifySVG(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "removes newlines",
			input:    []byte("<svg>\n  <path />\n</svg>"),
			expected: "<svg>  <path /></svg>",
		},
		{
			name:     "removes carriage returns",
			input:    []byte("<svg>\r\n  <path />\r\n</svg>"),
			expected: "<svg>  <path /></svg>",
		},
		{
			name:     "removes single line comment",
			input:    []byte("<svg><!-- comment --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes multi-line comment",
			input:    []byte("<svg><!-- \ncomment\n --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes multiple comments",
			input:    []byte("<svg><!-- first --><!-- second --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes newlines and comments together",
			input:    []byte("<svg>\n<!-- comment -->\n<path />\n</svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "handles empty input",
			input:    []byte(""),
			expected: "",
		},
		{
			name:     "handles input with no newlines or comments",
			input:    []byte("<svg><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name: "handles complex SVG",
			input: []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">
  <!-- Icon definition -->
  <g fill="none" stroke="currentColor">
    <path d="M12 2L2 7l10 5 10-5-10-5z"/>
    <!-- Second path -->
    <path d="M2 17l10 5 10-5"/>
  </g>
</svg>`),
			expected: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">    <g fill="none" stroke="currentColor">    <path d="M12 2L2 7l10 5 10-5-10-5z"/>        <path d="M2 17l10 5 10-5"/>  </g></svg>`,
		},
		{
			name:     "handles comment without closing tag",
			input:    []byte("<svg><!-- unclosed<path /></svg>"),
			expected: "<svg><!-- unclosed<path /></svg>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := minifySVG(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
