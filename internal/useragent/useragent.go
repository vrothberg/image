package useragent

import (
	"github.com/containers/image/v5/types"
	"github.com/containers/image/v5/version"
)

var defaultUserAgent = "containers/" + version.Version + " (github.com/containers/image)"

// UserAgent returns the user agent which can be customized via the system
// context's DockerRegistryUserAgent.
func UserAgent(sys *types.SystemContext) string {
	userAgent := defaultUserAgent
	if sys != nil && sys.DockerRegistryUserAgent != "" {
		userAgent = sys.DockerRegistryUserAgent
	}
	return userAgent
}
