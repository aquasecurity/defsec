package ecr

import (
	"fmt"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/liamg/iamgo"
)

func getRepositories(ctx parser.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourcesByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {

		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				Metadata:   r.Metadata(),
				ScanOnPush: types2.BoolDefault(false, r.Metadata()),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Policies:           nil,
			Encryption: ecr.Encryption{
				Metadata: r.Metadata(),
				Type:     types2.StringDefault(ecr.EncryptionTypeAES256, r.Metadata()),
				KMSKeyID: types2.StringDefault("", r.Metadata()),
			},
		}

		if imageScanningProp := r.GetProperty("ImageScanningConfiguration"); imageScanningProp.IsNotNil() {
			repository.ImageScanning = ecr.ImageScanning{
				Metadata:   imageScanningProp.Metadata(),
				ScanOnPush: imageScanningProp.GetBoolProperty("ScanOnPush", false),
			}
		}

		if encProp := r.GetProperty("EncryptionConfiguration"); encProp.IsNotNil() {
			repository.Encryption = ecr.Encryption{
				Metadata: encProp.Metadata(),
				Type:     encProp.GetStringProperty("EncryptionType", ecr.EncryptionTypeAES256),
				KMSKeyID: encProp.GetStringProperty("KmsKey", ""),
			}
		}

		if policy, err := getPolicy(r); err == nil {
			repository.Policies = append(repository.Policies, *policy)
		}

		repositories = append(repositories, repository)
	}

	return repositories
}

func getPolicy(r *parser.Resource) (*iam.Policy, error) {
	policyProp := r.GetProperty("RepositoryPolicyText")
	if policyProp.IsNil() {
		return nil, fmt.Errorf("missing policy")
	}

	parsed, err := iamgo.Parse(policyProp.GetJsonBytes())
	if err != nil {
		return nil, err
	}

	return &iam.Policy{
		Metadata: policyProp.Metadata(),
		Name:     types2.StringDefault("", policyProp.Metadata()),
		Document: iam.Document{
			Metadata: policyProp.Metadata(),
			Parsed:   *parsed,
		},
		Builtin: types2.Bool(false, policyProp.Metadata()),
	}, nil
}

func hasImmutableImageTags(r *parser.Resource) types2.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() {
		return types2.BoolDefault(false, r.Metadata())
	}
	if !mutabilityProp.EqualTo("IMMUTABLE") {
		return types2.Bool(false, mutabilityProp.Metadata())
	}
	return types2.Bool(true, mutabilityProp.Metadata())
}
