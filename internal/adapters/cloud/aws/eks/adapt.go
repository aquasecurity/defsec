package eks

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/state"
	eksapi "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type adapter struct {
	*aws.RootAdapter
	api *eksapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "eks"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = eksapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EKS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]eks.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var clusterNames []string
	var input eksapi.ListClustersInput
	for {
		output, err := a.api.ListClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		clusterNames = append(clusterNames, output.Clusters...)
		a.Tracker().SetTotalResources(len(clusterNames))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")

	var clusters []eks.Cluster

	for _, arn := range clusterNames {
		cluster, err := a.adaptCluster(arn)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, *cluster)
		a.Tracker().IncrementResource()
	}

	return clusters, nil
}

// nolint
func (a *adapter) adaptCluster(name string) (*eks.Cluster, error) {

	output, err := a.api.DescribeCluster(a.Context(), &eksapi.DescribeClusterInput{
		Name: &name,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*output.Cluster.Arn)

	var publicAccess bool
	var publicCidrs []defsecTypes.StringValue
	if output.Cluster.ResourcesVpcConfig != nil {
		publicAccess = output.Cluster.ResourcesVpcConfig.EndpointPublicAccess
		for _, cidr := range output.Cluster.ResourcesVpcConfig.PublicAccessCidrs {
			publicCidrs = append(publicCidrs, defsecTypes.String(cidr, metadata))
		}
	}

	var encryptionKeyARN string
	var secretsEncrypted bool
	for _, config := range output.Cluster.EncryptionConfig {
		if config.Provider != nil && config.Provider.KeyArn != nil {
			encryptionKeyARN = *config.Provider.KeyArn
		}
		if len(config.Resources) > 0 {
			for _, resource := range config.Resources {
				if resource == "secrets" {
					secretsEncrypted = true
				}
			}
		}
	}

	var logAPI, logAudit, logAuth, logCM, logSched bool
	if output.Cluster.Logging != nil {
		for _, logging := range output.Cluster.Logging.ClusterLogging {
			if logging.Enabled == nil || !*logging.Enabled {
				continue
			}
			for _, logType := range logging.Types {
				switch logType {
				case types.LogTypeApi:
					logAPI = true
				case types.LogTypeAudit:
					logAudit = true
				case types.LogTypeAuthenticator:
					logAuth = true
				case types.LogTypeControllerManager:
					logCM = true
				case types.LogTypeScheduler:
					logSched = true
				}
			}
		}
	}

	return &eks.Cluster{
		Metadata: metadata,
		Logging: eks.Logging{
			Metadata:          metadata,
			API:               defsecTypes.Bool(logAPI, metadata),
			Audit:             defsecTypes.Bool(logAudit, metadata),
			Authenticator:     defsecTypes.Bool(logAuth, metadata),
			ControllerManager: defsecTypes.Bool(logCM, metadata),
			Scheduler:         defsecTypes.Bool(logSched, metadata),
		},
		Encryption: eks.Encryption{
			Metadata: metadata,
			Secrets:  defsecTypes.Bool(secretsEncrypted, metadata),
			KMSKeyID: defsecTypes.String(encryptionKeyARN, metadata),
		},
		PublicAccessEnabled: defsecTypes.Bool(publicAccess, metadata),
		PublicAccessCIDRs:   publicCidrs,
	}, nil
}
