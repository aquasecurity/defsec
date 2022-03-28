package mq

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/mq"
)

func Test_adaptBroker(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  mq.Broker
	}{
		{
			name: "audit logs",
			terraform: `
			resource "aws_mq_broker" "example" {
				logs {
				  audit = true
				}

				publicly_accessible = false
			  }
`,
			expected: mq.Broker{
				Metadata:     types.NewTestMetadata(),
				PublicAccess: types.Bool(false, types.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: types.NewTestMetadata(),
					General:  types.Bool(false, types.NewTestMetadata()),
					Audit:    types.Bool(true, types.NewTestMetadata()),
				},
			},
		},
		{
			name: "general logs",
			terraform: `
			resource "aws_mq_broker" "example" {
				logs {
				  general = true
				}

				publicly_accessible = true
			  }
`,
			expected: mq.Broker{
				Metadata:     types.NewTestMetadata(),
				PublicAccess: types.Bool(true, types.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: types.NewTestMetadata(),
					General:  types.Bool(true, types.NewTestMetadata()),
					Audit:    types.Bool(false, types.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_mq_broker" "example" {
			  }
`,
			expected: mq.Broker{
				Metadata:     types.NewTestMetadata(),
				PublicAccess: types.Bool(false, types.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: types.NewTestMetadata(),
					General:  types.Bool(false, types.NewTestMetadata()),
					Audit:    types.Bool(false, types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptBroker(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_mq_broker" "example" {
		logs {
		  general = true
		}

		publicly_accessible = true
	  }`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.Brokers, 1)
	broker := adapted.Brokers[0]

	assert.Equal(t, 2, broker.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, broker.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, broker.Logging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, broker.Logging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, broker.Logging.General.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, broker.Logging.General.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, broker.PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, broker.PublicAccess.GetMetadata().Range().GetEndLine())
}
