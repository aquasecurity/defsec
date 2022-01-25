package workspaces

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/aws/workspaces"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckEnableDiskEncryption(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input workspaces.WorkSpaces
        expected bool
    }{
        {
            name: "positive result",
            input: workspaces.WorkSpaces{},
            expected: true,
        },
        {
            name: "negative result",
            input: workspaces.WorkSpaces{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.AWS.WorkSpaces = test.input
            results := CheckEnableDiskEncryption.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckEnableDiskEncryption.Rule().LongID() {
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
