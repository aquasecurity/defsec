package azure

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableAZUREScanner interface {
	options.ConfigurableScanner
	SetProgressTracker(t progress.Tracker)
	SetAZURELocation(location string)
	SetAZUREEndpoint(endpoint string)
	SetAZUREServices(services []string)
	SetConcurrencyStrategy(strategy concurrency.Strategy)
}

func ScannerWithProgressTracker(t progress.Tracker) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAZUREScanner); ok {
			azure.SetProgressTracker(t)
		}
	}
}

func ScannerWithAZURELocation(location string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAZUREScanner); ok {
			azure.SetAZURELocation(location)
		}
	}
}

func ScannerWithAZUREEndpoint(endpoint string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAZUREScanner); ok {
			azure.SetAZUREEndpoint(endpoint)
		}
	}
}

func ScannerWithAZUREServices(services ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAZUREScanner); ok {
			azure.SetAZUREServices(services)
		}
	}
}

func ScannerWithConcurrencyStrategy(strategy concurrency.Strategy) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAZUREScanner); ok {
			azure.SetConcurrencyStrategy(strategy)
		}
	}
}
