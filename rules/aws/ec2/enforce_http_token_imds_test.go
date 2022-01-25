package ec2

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/aws/ec2"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckIMDSAccessRequiresToken(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input ec2.EC2
        expected bool
    }{
        {
            name: "positive result",
            input: ec2.EC2{},
            expected: true,
        },
        {
            name: "negative result",
            input: ec2.EC2{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.AWS.EC2 = test.input
            results := CheckIMDSAccessRequiresToken.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckIMDSAccessRequiresToken.Rule().LongID() {
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
