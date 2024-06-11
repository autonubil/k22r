package main

import (
	"os/user"
	"time"

	"github.com/autonubil/k22r/cmd"
	"github.com/autonubil/k22r/pkg/build"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	if date == "unknown" {
		date = time.Now().Format(time.RFC3339)
	}
	if builtBy == "unknown" {
		user, err := user.Current()
		if err == nil {
			builtBy = user.Name
		}
	}
	build.Info = build.NewBuildInfo(version, commit, date, builtBy)
	cmd.Execute()
}
