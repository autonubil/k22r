package build

import (
	"fmt"
	"os"
)

var (
	// Build build information
	Info BuildInfo
)

// BuildInfo build information
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
	BuiltBy string
}

// NewBuildInfo create new build information
func NewBuildInfo(version, commit, date, builtBy string) BuildInfo {
	return BuildInfo{version, commit, date, builtBy}
}

// Release get release to be used with sentry
func (b *BuildInfo) Release() string {
	if b.Version == "dev" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "dev"
		}
		return fmt.Sprintf("%s+%s", hostname, b.Commit)
	}
	return fmt.Sprintf("%s+%s", b.Version, b.Commit)
}
