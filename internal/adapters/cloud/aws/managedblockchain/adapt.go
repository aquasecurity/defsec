package managedblockchain

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/managedblockchain"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/managedblockchain"
	"github.com/aws/aws-sdk-go-v2/service/managedblockchain/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "managedblockchain"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ManagedBlockchain.Members, err = a.getMembers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getMembers() ([]managedblockchain.Member, error) {

	a.Tracker().SetServiceLabel("Discovering members...")

	var apimembers []types.MemberSummary
	var input api.ListNetworksInput
	output, err := a.api.ListNetworks(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	for _, network := range output.Networks {
		members, err := a.api.ListMembers(a.Context(), &api.ListMembersInput{
			NetworkId: network.Id,
		})
		if err != nil {
			return nil, err
		}

		apimembers = append(apimembers, members.Members...)
		a.Tracker().SetTotalResources(len(apimembers))
		if members.NextToken == nil {
			break
		}
		input.NextToken = members.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting member...")
	return concurrency.Adapt(apimembers, a.RootAdapter, a.adaptMember), nil
}

func (a *adapter) adaptMember(member types.MemberSummary) (*managedblockchain.Member, error) {

	metadata := a.CreateMetadataFromARN(*member.Arn)

	output, err := a.api.GetMember(a.Context(), &api.GetMemberInput{
		MemberId: member.Id,
	})
	if err != nil {
		return nil, err
	}

	return &managedblockchain.Member{
		Metadata:  metadata,
		KmsKeyArn: defsecTypes.String(*output.Member.KmsKeyArn, metadata),
	}, nil
}
