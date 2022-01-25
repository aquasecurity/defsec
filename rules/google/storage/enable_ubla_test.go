package storage

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/google/storage"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckEnableUbla(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input storage.Storage
        expected bool
    }{
        {
            name: "positive result",
            input: storage.Storage{},
            expected: true,
        },
        {
            name: "negative result",
            input: storage.Storage{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.Google.Storage = test.input
            results := CheckEnableUbla.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckEnableUbla.Rule().LongID() {
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
