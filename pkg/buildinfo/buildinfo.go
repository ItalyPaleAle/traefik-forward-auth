package buildinfo

import (
	"fmt"

	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

// These variables will be set at build time
var (
	AppName    string = "traefik-forward-auth"
	AppVersion string = "canary"
	BuildId    string
	CommitHash string
	BuildDate  string
	Production string
)

// Set during initialization
var BuildDescription string

func init() {
	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}

	if !utils.IsTruthy(Production) {
		BuildDescription += " (non-production)"
	}
}
