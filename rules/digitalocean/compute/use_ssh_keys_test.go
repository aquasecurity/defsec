package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSshKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Droplet missing SSH keys",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Droplets: []compute.Droplet{
					{
						Metadata: types.NewTestMetadata(),
						SSHKeys:  []types.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "Droplet with an SSH key provided",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Droplets: []compute.Droplet{
					{
						Metadata: types.NewTestMetadata(),
						SSHKeys: []types.StringValue{
							types.String("my-ssh-key", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.DigitalOcean.Compute = test.input
			results := CheckUseSshKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckUseSshKeys.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
