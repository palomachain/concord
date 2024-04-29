package config

import (
	"fmt"
	"strings"
)

var (
	version string
	commit  string
)

func Version() string {
	if !strings.HasPrefix(version, "v") {
		version = fmt.Sprintf("v%s", version)
	}

	return version
}

func Commit() string { return commit }
