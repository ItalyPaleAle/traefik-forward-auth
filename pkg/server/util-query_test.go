package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestQueryValue(t *testing.T) {
	newContext := func(target string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, target, nil)
		return c
	}

	t.Run("matches Query when there is a query string", func(t *testing.T) {
		targets := []string{
			"/?logout=1",
			"/?logout=1&html=true",
			"/?logout=",
			"/?other=1",
			"/?logout=1&logout=2",
			"/?logout=%20yes%20",
		}

		for _, target := range targets {
			t.Run(target, func(t *testing.T) {
				for _, key := range []string{"logout", "html", "missing"} {
					c := newContext(target)
					assert.Equalf(t, c.Query(key), queryValue(c, key), "key %q", key)
				}
			})
		}
	})

	t.Run("returns an empty string without a query string", func(t *testing.T) {
		c := newContext("/")
		assert.Empty(t, queryValue(c, "logout"))
	})

	t.Run("does not parse the query string when there is none", func(t *testing.T) {
		c := newContext("/")

		allocs := testing.AllocsPerRun(100, func() {
			_ = queryValue(c, "logout")
		})

		assert.Zero(t, allocs)
	})

	t.Run("tolerates a context without a request", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		assert.Empty(t, queryValue(c, "logout"))
	})
}
