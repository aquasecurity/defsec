package dynamodb

import (
    "testing"

    "github.com/aquasecurity/defsec/provider/aws/dynamodb"
    "github.com/aquasecurity/defsec/state"
    "github.com/stretchr/testify/assert"
)

func TestCheckEnableRecovery(t *testing.T) {
    t.SkipNow()
    tests := []struct{
        name string
        input dynamodb.DynamoDB
        expected bool
    }{
        {
            name: "positive result",
            input: dynamodb.DynamoDB{},
            expected: true,
        },
        {
            name: "negative result",
            input: dynamodb.DynamoDB{},
            expected: false,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T){
            var testState state.State
            testState.AWS.DynamoDB = test.input
            results := CheckEnableRecovery.Evaluate(&testState)
            var found bool
            for _, result := range results {
                if result.Rule().LongID() == CheckEnableRecovery.Rule().LongID() {
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
