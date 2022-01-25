package synapse

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/azure/synapse"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckVirtualNetworkEnabled(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input synapse.Synapse
        expected bool
    }{
        {
            name: "positive result",
            input: synapse.Synapse{},
            expected: true,
        },
        {
            name: "negative result",
            input: synapse.Synapse{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.Azure.Synapse = test.input
            results := CheckVirtualNetworkEnabled.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckVirtualNetworkEnabled.Rule().LongID() {
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
