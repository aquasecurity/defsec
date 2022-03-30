package msk

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters []msk.Cluster) {
	for _, r := range ctx.GetResourcesByType("AWS::MSK::Cluster") {

		cluster := msk.Cluster{
			Metadata: r.Metadata(),
			EncryptionInTransit: msk.EncryptionInTransit{
				Metadata:     r.Metadata(),
				ClientBroker: types.StringDefault("TLS", r.Metadata()),
			},
			Logging: msk.Logging{
				Metadata: r.Metadata(),
				Broker: msk.BrokerLogging{
					Metadata: r.Metadata(),
					S3: msk.S3Logging{
						Metadata: r.Metadata(),
						Enabled:  types.BoolDefault(false, r.Metadata()),
					},
					Cloudwatch: msk.CloudwatchLogging{
						Metadata: r.Metadata(),
						Enabled:  types.BoolDefault(false, r.Metadata()),
					},
					Firehose: msk.FirehoseLogging{
						Metadata: r.Metadata(),
						Enabled:  types.BoolDefault(false, r.Metadata()),
					},
				},
			},
		}

		if encProp := r.GetProperty("EncryptionInfo.EncryptionInTransit"); encProp.IsNotNil() {
			cluster.EncryptionInTransit = msk.EncryptionInTransit{
				Metadata:     encProp.Metadata(),
				ClientBroker: encProp.GetStringProperty("ClientBroker", "TLS"),
			}
		}
		if loggingProp := r.GetProperty("LoggingInfo"); loggingProp.IsNotNil() {
			cluster.Logging.Metadata = loggingProp.Metadata()
			if brokerLoggingProp := loggingProp.GetProperty("BrokerLogs"); brokerLoggingProp.IsNotNil() {
				cluster.Logging.Broker.Metadata = brokerLoggingProp.Metadata()
				if s3Prop := brokerLoggingProp.GetProperty("S3"); s3Prop.IsNotNil() {
					cluster.Logging.Broker.S3.Metadata = s3Prop.Metadata()
					cluster.Logging.Broker.S3.Enabled = s3Prop.GetBoolProperty("Enabled", false)
				}
				if cwProp := brokerLoggingProp.GetProperty("CloudWatchLogs"); cwProp.IsNotNil() {
					cluster.Logging.Broker.Cloudwatch.Metadata = cwProp.Metadata()
					cluster.Logging.Broker.Cloudwatch.Enabled = cwProp.GetBoolProperty("Enabled", false)
				}
				if fhProp := brokerLoggingProp.GetProperty("Firehose"); fhProp.IsNotNil() {
					cluster.Logging.Broker.Firehose.Metadata = fhProp.Metadata()
					cluster.Logging.Broker.Firehose.Enabled = fhProp.GetBoolProperty("Enabled", false)
				}
			}
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}
