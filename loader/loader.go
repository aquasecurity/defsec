package loader

import (
	"strings"

	"github.com/aquasecurity/defsec/rules"
)

func GetProviders() []string {

	registeredRules := rules.GetRegistered()

	providers := make(map[string]bool)

	for _, rule := range registeredRules {

		if _, ok := providers[rule.Rule().Provider.DisplayName()]; !ok {
			providers[rule.Rule().Provider.DisplayName()] = true
		}

	}

	var uniqueProviders []string
	for p := range providers {
		uniqueProviders = append(uniqueProviders, p)
	}

	return uniqueProviders

}

func GetProviderServices(providerName string) []string {

	registeredRules := rules.GetRegistered()

	services := make(map[string]bool)

	for _, rule := range registeredRules {

		if strings.ToLower(providerName) != strings.ToLower(rule.Rule().Provider.DisplayName()) {
			continue
		}

		if _, ok := services[rule.Rule().Service]; !ok {
			services[rule.Rule().Service] = true
		}

	}
	var uniqueServices []string
	for p := range services {
		uniqueServices = append(uniqueServices, p)
	}

	return uniqueServices
}

func GetProviderServiceChecks(providerName string, serviceName string) []string {

	registeredRules := rules.GetRegistered()

	var checks []string

	for _, rule := range registeredRules {

		if strings.ToLower(providerName) != strings.ToLower(rule.Rule().Provider.DisplayName()) ||
			strings.ToLower(serviceName) != strings.ToLower(rule.Rule().Service) {
			continue
		}

		checks = append(checks, rule.Rule().AVDID)
	}
	return checks
}
