package main

import (
	"fmt"
	"net/http"

	internal "github.com/italypaleale/traefik-forward-auth/internal"
)

// Main
func main() {
	// Parse options
	config := internal.NewGlobalConfig()

	// Setup logger
	log := internal.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	// Build server
	server := internal.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on %s:%d", config.Bind, config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf("%s:%d", config.Bind, config.Port), nil))
}
