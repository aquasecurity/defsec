package azure

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableAzureScanner interface {
	options.ConfigurableScanner
	SetProgressTracker(t progress.Tracker)
	SetAzureRegion(region string)
	SetAzureEndpoint(endpoint string)
	SetAzureServices(services []string)
	SetConcurrencyStrategy(strategy concurrency.Strategy)
}

func ScannerWithProgressTracker(t progress.Tracker) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAzureScanner); ok {
			azure.SetProgressTracker(t)
		}
	}
}

func ScannerWithAzureRegion(region string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAzureScanner); ok {
			azure.SetAzureRegion(region)
		}
	}
}

func ScannerWithAzureEndpoint(endpoint string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAzureScanner); ok {
			azure.SetAzureEndpoint(endpoint)
		}
	}
}

func ScannerWithAzureServices(services ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAzureScanner); ok {
			azure.SetAzureServices(services)
		}
	}
}

func ScannerWithConcurrencyStrategy(strategy concurrency.Strategy) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if azure, ok := s.(ConfigurableAzureScanner); ok {
			azure.SetConcurrencyStrategy(strategy)
		}
	}
}
