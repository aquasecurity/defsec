package iam

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/google/iam"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckNoOrgLevelDefaultServiceAccountAssignment(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input iam.IAM
        expected bool
    }{
        {
            name: "positive result",
            input: iam.IAM{},
            expected: true,
        },
        {
            name: "negative result",
            input: iam.IAM{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.Google.IAM = test.input
            results := CheckNoOrgLevelDefaultServiceAccountAssignment.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckNoOrgLevelDefaultServiceAccountAssignment.Rule().LongID() {
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
