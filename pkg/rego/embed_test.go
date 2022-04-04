package rego

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/stretchr/testify/assert"
)

func Test_EmbeddedLoading(t *testing.T) {

	rules := rules.GetRegistered()
	var found bool
	for _, rule := range rules {
		if rule.Rule().RegoPackage != "" {
			found = true
		}
	}
	assert.True(t, found, "no embedded rego policies were registered as rules")
}
