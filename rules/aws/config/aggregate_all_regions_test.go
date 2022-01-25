package config

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/aws/config"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckAggregateAllRegions(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input config.Config
        expected bool
    }{
        {
            name: "positive result",
            input: config.Config{},
            expected: true,
        },
        {
            name: "negative result",
            input: config.Config{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.AWS.Config = test.input
            results := CheckAggregateAllRegions.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckAggregateAllRegions.Rule().LongID() {
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
