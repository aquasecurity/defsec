package tests

import (
	"testing"

	"github.com/aquasecurity/defsec/loader"
	"github.com/stretchr/testify/assert"
)

func Test_loader_returns_expected_providers(t *testing.T) {
	providers := loader.GetProviders()
	assert.Len(t, providers, 9)
}

func Test_load_returns_expected_services(t *testing.T) {
	services := loader.GetProviderServices("aws")
	assert.Len(t, services, 35)
}

func Test_load_returns_expected_service_checks(t *testing.T) {
	checks := loader.GetProviderServiceChecks("aws", "s3")
	assert.Len(t, checks, 9)
}
