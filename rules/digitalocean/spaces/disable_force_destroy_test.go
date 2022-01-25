package spaces

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/digitalocean/spaces"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckDisableForceDestroy(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input spaces.Spaces
        expected bool
    }{
        {
            name: "positive result",
            input: spaces.Spaces{},
            expected: true,
        },
        {
            name: "negative result",
            input: spaces.Spaces{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.DigitalOcean.Spaces = test.input
            results := CheckDisableForceDestroy.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckDisableForceDestroy.Rule().LongID() {
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
