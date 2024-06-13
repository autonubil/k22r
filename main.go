package main

import (
	"os/user"
	"time"

	"github.com/autonubil/k22r/cmd"
	"github.com/autonubil/k22r/pkg/build"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
	BuiltBy = "unknown"
)

func main() {
	if Date == "unknown" {
		Date = time.Now().Format(time.RFC3339)
	}
	if BuiltBy == "unknown" {
		user, err := user.Current()
		if err == nil {
			BuiltBy = user.Name
		}
	}
	build.Info = build.NewBuildInfo(Version, Commit, Date, BuiltBy)
	cmd.Execute()
}
