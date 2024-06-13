package main

import (
	"os/user"
	"time"

	"github.com/autonubil/k22r/cmd"
	"github.com/autonubil/k22r/pkg/build"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
	BuildBy   = "unknown"
)

func main() {
	if BuildDate == "unknown" {
		BuildDate = time.Now().Format(time.RFC3339)
	}
	if BuildBy == "unknown" {
		user, err := user.Current()
		if err == nil {
			BuildBy = user.Name
		}
	}
	build.Info = build.NewBuildInfo(Version, Commit, BuildDate, BuildBy)
	cmd.Execute()
}
