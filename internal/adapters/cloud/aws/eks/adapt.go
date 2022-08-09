package eks

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/state"
	types2 "github.com/aquasecurity/defsec/pkg/types"
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

	for _, clusterName := range clusterNames {
		cluster, err := a.adaptCluster(clusterName)
		if err != nil {
			a.Debug("Failed to adapt cluster '%s': %s", clusterName, err)
			continue
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
	var publicCidrs []types2.StringValue
	if output.Cluster.ResourcesVpcConfig != nil {
		publicAccess = output.Cluster.ResourcesVpcConfig.EndpointPublicAccess
		for _, cidr := range output.Cluster.ResourcesVpcConfig.PublicAccessCidrs {
			publicCidrs = append(publicCidrs, types2.String(cidr, metadata))
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
			API:               types2.Bool(logAPI, metadata),
			Audit:             types2.Bool(logAudit, metadata),
			Authenticator:     types2.Bool(logAuth, metadata),
			ControllerManager: types2.Bool(logCM, metadata),
			Scheduler:         types2.Bool(logSched, metadata),
		},
		Encryption: eks.Encryption{
			Metadata: metadata,
			Secrets:  types2.Bool(secretsEncrypted, metadata),
			KMSKeyID: types2.String(encryptionKeyARN, metadata),
		},
		PublicAccessEnabled: types2.Bool(publicAccess, metadata),
		PublicAccessCIDRs:   publicCidrs,
	}, nil
}
