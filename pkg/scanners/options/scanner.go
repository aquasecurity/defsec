package options

import (
	"io"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/progress"
)

type ConfigurableScanner interface {
	SetDebugWriter(io.Writer)
	SetTraceWriter(io.Writer)
	SetPerResultTracingEnabled(bool)
	SetPolicyDirs(...string)
	SetDataDirs(...string)
	SetPolicyNamespaces(...string)
	SetSkipRequiredCheck(bool)
	SetPolicyReaders([]io.Reader)
	SetPolicyFilesystem(fs.FS)
	SetUseEmbeddedPolicies(bool)
	SetProgressTracker(t progress.Tracker)
}

type ScannerOption func(s ConfigurableScanner)

func ScannerWithPolicyReader(readers ...io.Reader) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyReaders(readers)
	}
}

func ScannerWithProgressTracker(t progress.Tracker) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetProgressTracker(t)
	}

}

// ScannerWithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func ScannerWithDebug(w io.Writer) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDebugWriter(w)
	}
}

func ScannerWithEmbeddedPolicies(embedded bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetUseEmbeddedPolicies(embedded)
	}
}

// ScannerWithTrace specifies an io.Writer for trace logs (mainly rego tracing) - if not set, they are discarded
func ScannerWithTrace(w io.Writer) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetTraceWriter(w)
	}
}

func ScannerWithPerResultTracing(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPerResultTracingEnabled(enabled)
	}
}

func ScannerWithPolicyDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyDirs(paths...)
	}
}

func ScannerWithDataDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDataDirs(paths...)
	}
}

// ScannerWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func ScannerWithPolicyNamespaces(namespaces ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyNamespaces(namespaces...)
	}
}

func ScannerWithSkipRequiredCheck(skip bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetSkipRequiredCheck(skip)
	}
}

func ScannerWithPolicyFilesystem(f fs.FS) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyFilesystem(f)
	}
}
