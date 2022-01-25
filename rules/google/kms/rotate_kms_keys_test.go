package kms

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/google/kms"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckRotateKmsKeys(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input kms.KMS
        expected bool
    }{
        {
            name: "positive result",
            input: kms.KMS{},
            expected: true,
        },
        {
            name: "negative result",
            input: kms.KMS{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.Google.KMS = test.input
            results := CheckRotateKmsKeys.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckRotateKmsKeys.Rule().LongID() {
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
