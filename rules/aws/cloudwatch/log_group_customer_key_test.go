package cloudwatch

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/aws/cloudwatch"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckLogGroupCustomerKey(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input cloudwatch.CloudWatch
        expected bool
    }{
        {
            name: "positive result",
            input: cloudwatch.CloudWatch{},
            expected: true,
        },
        {
            name: "negative result",
            input: cloudwatch.CloudWatch{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.AWS.CloudWatch = test.input
            results := CheckLogGroupCustomerKey.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckLogGroupCustomerKey.Rule().LongID() {
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
