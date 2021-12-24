package tests

import (
	"testing"

	"github.com/aquasecurity/defsec/loader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_loader_returns_expected_providers(t *testing.T) {
	providers := loader.GetProviderNames()
	assert.Len(t, providers, 10)
}

func Test_load_returns_expected_services(t *testing.T) {
	services := loader.GetProviderServiceNames("aws")
	assert.Len(t, services, 35)
}

func Test_load_returns_expected_service_checks(t *testing.T) {
	checks := loader.GetProviderServiceCheckNames("aws", "s3")
	assert.Len(t, checks, 9)
}

func Test_get_providers(t *testing.T) {
	dataset := loader.GetProviders()
	assert.Len(t, dataset, 10)
}

func Test_get_providers_as_Json(t *testing.T) {
	jsonData, err := loader.GetProvidersAsJson()
	require.NoError(t, err)

	assert.NotEmpty(t, jsonData)
}

func Test_get_provider_hierarchy(t *testing.T) {
	hierarchy := loader.GetProvidersHierarchy()

	var providers []string

	for provider := range hierarchy {
		providers = append(providers, provider)
	}

	assert.Len(t, providers, 10)
}
