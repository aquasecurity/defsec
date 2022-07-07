package options

import (
	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/progress"
)

type Options struct {
	ProgressTracker progress.Tracker
	Region          string
	Endpoint        string
	Services        []string
	DebugWriter     debug.Logger
}
