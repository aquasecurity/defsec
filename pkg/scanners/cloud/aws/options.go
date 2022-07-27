package aws

import (
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableAWSScanner interface {
	options.ConfigurableScanner
	SetProgressTracker(t progress.Tracker)
	SetAWSRegion(region string)
	SetAWSEndpoint(endpoint string)
	SetAWSServices(services []string)
}

func ScannerWithProgressTracker(t progress.Tracker) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if aws, ok := s.(ConfigurableAWSScanner); ok {
			aws.SetProgressTracker(t)
		}
	}
}

func ScannerWithAWSRegion(region string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if aws, ok := s.(ConfigurableAWSScanner); ok {
			aws.SetAWSRegion(region)
		}
	}
}

func ScannerWithAWSEndpoint(endpoint string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if aws, ok := s.(ConfigurableAWSScanner); ok {
			aws.SetAWSEndpoint(endpoint)
		}
	}
}

func ScannerWithAWSServices(services ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if aws, ok := s.(ConfigurableAWSScanner); ok {
			aws.SetAWSServices(services)
		}
	}
}
