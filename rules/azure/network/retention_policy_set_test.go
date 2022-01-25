package network

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/azure/network"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckRetentionPolicySet(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input network.Network
        expected bool
    }{
        {
            name: "positive result",
            input: network.Network{},
            expected: true,
        },
        {
            name: "negative result",
            input: network.Network{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.Azure.Network = test.input
            results := CheckRetentionPolicySet.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckRetentionPolicySet.Rule().LongID() {
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
