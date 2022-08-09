package msk

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  msk.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_msk_cluster" "example" {
				cluster_name           = "example"

				encryption_info {
					encryption_in_transit {
						client_broker = "TLS"
						in_cluster = true
					}
				}
			  
				logging_info {
				  broker_logs {
					cloudwatch_logs {
					  enabled   = true
					  log_group = aws_cloudwatch_log_group.test.name
					}
					firehose {
					  enabled         = true
					  delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
					}
					s3 {
					  enabled = true
					  bucket  = aws_s3_bucket.bucket.id
					  prefix  = "logs/msk-"
					}
				  }
				}
			  }
`,
			expected: msk.Cluster{
				Metadata: defsecTypes.NewTestMetadata(),
				EncryptionInTransit: msk.EncryptionInTransit{
					Metadata:     defsecTypes.NewTestMetadata(),
					ClientBroker: defsecTypes.String("TLS", defsecTypes.NewTestMetadata()),
				},
				Logging: msk.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Broker: msk.BrokerLogging{
						Metadata: defsecTypes.NewTestMetadata(),
						S3: msk.S3Logging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						Cloudwatch: msk.CloudwatchLogging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						Firehose: msk.FirehoseLogging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_msk_cluster" "example" {
			  }
`,
			expected: msk.Cluster{
				Metadata: defsecTypes.NewTestMetadata(),
				EncryptionInTransit: msk.EncryptionInTransit{
					Metadata:     defsecTypes.NewTestMetadata(),
					ClientBroker: defsecTypes.String("TLS_PLAINTEXT", defsecTypes.NewTestMetadata()),
				},
				Logging: msk.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Broker: msk.BrokerLogging{
						Metadata: defsecTypes.NewTestMetadata(),
						S3: msk.S3Logging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						Cloudwatch: msk.CloudwatchLogging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						Firehose: msk.FirehoseLogging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_msk_cluster" "example" {
		cluster_name           = "example"

		encryption_info {
			encryption_in_transit {
				client_broker = "TLS"
				in_cluster = true
			}
		}
	  
		logging_info {
		  broker_logs {
			cloudwatch_logs {
			  enabled   = true
			  log_group = aws_cloudwatch_log_group.test.name
			}
			firehose {
			  enabled         = true
			  delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
			}
			s3 {
			  enabled = true
			  bucket  = aws_s3_bucket.bucket.id
			  prefix  = "logs/msk-"
			}
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.EncryptionInTransit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, cluster.EncryptionInTransit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, cluster.Logging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, cluster.Logging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, cluster.Logging.Broker.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 27, cluster.Logging.Broker.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, cluster.Logging.Broker.Cloudwatch.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, cluster.Logging.Broker.Cloudwatch.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, cluster.Logging.Broker.Cloudwatch.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, cluster.Logging.Broker.Cloudwatch.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, cluster.Logging.Broker.Firehose.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, cluster.Logging.Broker.Firehose.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, cluster.Logging.Broker.Firehose.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, cluster.Logging.Broker.Firehose.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, cluster.Logging.Broker.S3.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, cluster.Logging.Broker.S3.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, cluster.Logging.Broker.S3.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, cluster.Logging.Broker.S3.Enabled.GetMetadata().Range().GetEndLine())
}
