package emr

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	types.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types.Metadata
	Name         types.StringValue
	ReleaseLabel types.StringValue
	ServiceRole  types.StringValue
}

type SecurityConfiguration struct {
	types.Metadata
	Name          types.StringValue
	Configuration types.StringValue
}

// type Conf struct {
// 	types.Metadata
// 	EncryptionConfiguration struct {
// 		AtRestEncryptionConfiguration struct {
// 			S3EncryptionConfiguration struct {
// 				EncryptionMode string `json:"EncryptionMode"`
// 			} `json:"S3EncryptionConfiguration"`
// 			LocalDiskEncryptionConfiguration struct {
// 				EncryptionKeyProviderType string `json:"EncryptionKeyProviderType"`
// 				AwsKmsKey                 string `json:"AwsKmsKey"`
// 			} `json:"LocalDiskEncryptionConfiguration"`
// 		} `json:"AtRestEncryptionConfiguration"`
// 		EnableInTransitEncryption bool `json:"EnableInTransitEncryption"`
// 		EnableAtRestEncryption    bool `json:"EnableAtRestEncryption"`
// 	} `json:"EncryptionConfiguration"`
// }
