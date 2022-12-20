package msk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getClusters(ctx parser.FileContext) (clusters []msk.Cluster) {
	for _, r := range ctx.GetResourcesByType("AWS::MSK::Cluster") {

		cluster := msk.Cluster{
			Metadata: r.Metadata(),
			BrokerNodeGroupInfo: msk.BrokerNodeGroupInfo{
				Metadata: r.Metadata(),
				ConnectivityInfo: msk.ConnectivityInfo{
					Metadata: r.Metadata(),
					PublicAccess: msk.PublicAccess{
						Metadata: r.Metadata(),
						Type:     defsecTypes.StringDefault("DISABLED", r.Metadata()),
					},
				},
			},
			EncryptionInTransit: msk.EncryptionInTransit{
				Metadata:     r.Metadata(),
				ClientBroker: defsecTypes.StringDefault("TLS", r.Metadata()),
				InCluster:    defsecTypes.Bool(true, r.Metadata()),
			},
			EncryptionAtRest: msk.EncryptionAtRest{
				Metadata:  r.Metadata(),
				KMSKeyARN: defsecTypes.StringDefault("", r.Metadata()),
				Enabled:   defsecTypes.BoolDefault(false, r.Metadata()),
			},
			ClientAuthentication: msk.ClientAuthentication{
				Metadata: r.Metadata(),
				Unauthenticated: msk.Unauthenticated{
					Metadata: r.Metadata(),
					Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
				},
			},
			Logging: msk.Logging{
				Metadata: r.Metadata(),
				Broker: msk.BrokerLogging{
					Metadata: r.Metadata(),
					S3: msk.S3Logging{
						Metadata: r.Metadata(),
						Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
					},
					Cloudwatch: msk.CloudwatchLogging{
						Metadata: r.Metadata(),
						Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
					},
					Firehose: msk.FirehoseLogging{
						Metadata: r.Metadata(),
						Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
					},
				},
			},
		}

		if brokerNodeProp := r.GetProperty("BrokerNodeGroupInfo"); brokerNodeProp.IsNotNil() {
			cluster.BrokerNodeGroupInfo.Metadata = brokerNodeProp.Metadata()
			if connectInfoProp := brokerNodeProp.GetProperty("ConnectivityInfo"); connectInfoProp.IsNotNil() {
				cluster.BrokerNodeGroupInfo.ConnectivityInfo.Metadata = connectInfoProp.Metadata()
				if publicAcessProp := connectInfoProp.GetProperty("PublicAccess"); publicAcessProp.IsNotNil() {
					cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Metadata = publicAcessProp.Metadata()
					cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type = publicAcessProp.GetStringProperty("Type", "DISABLED")
				}
			}
		}

		if encProp := r.GetProperty("EncryptionInfo.EncryptionInTransit"); encProp.IsNotNil() {
			cluster.EncryptionInTransit = msk.EncryptionInTransit{
				Metadata:     encProp.Metadata(),
				ClientBroker: encProp.GetStringProperty("ClientBroker", "TLS"),
				InCluster:    encProp.GetBoolProperty("InCluster", true),
			}
		}

		if encAtRestProp := r.GetProperty("EncryptionInfo.EncryptionAtRest"); encAtRestProp.IsNotNil() {
			cluster.EncryptionAtRest = msk.EncryptionAtRest{
				Metadata:  encAtRestProp.Metadata(),
				KMSKeyARN: encAtRestProp.GetStringProperty("DataVolumeKMSKeyId", ""),
				Enabled:   defsecTypes.BoolDefault(true, encAtRestProp.Metadata()),
			}
		}

		if clientAuthProp := r.GetProperty("ClientAuthentication"); clientAuthProp.IsNotNil() {
			cluster.ClientAuthentication.Metadata = clientAuthProp.Metadata()
			if unauthProp := clientAuthProp.GetProperty("Unauthenticated"); unauthProp.IsNotNil() {
				cluster.ClientAuthentication.Unauthenticated.Metadata = unauthProp.Metadata()
				cluster.ClientAuthentication.Unauthenticated.Enabled = unauthProp.GetBoolProperty("Enabled", false)
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
