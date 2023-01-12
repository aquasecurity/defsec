package appmesh

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	appmeshApi "github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmeshTypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
)

type adapter struct {
	*aws2.RootAdapter
	client *appmeshApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Name() string {
	return "appmesh"
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.client = appmeshApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.AppMesh.Meshes, err = a.getmeshes()
	if err != nil {
		return err
	}

	// state.AWS.AppMesh.VirtualGateways, err = a.getvirtualgateways()
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (a *adapter) getmeshes() (mesh []appmesh.Mesh, err error) {

	a.Tracker().SetServiceLabel("Discovering AppMesh meshes...")
	var apiMesh []appmeshTypes.MeshRef
	var input appmeshApi.ListMeshesInput
	for {
		output, err := a.client.ListMeshes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiMesh = append(apiMesh, output.Meshes...)
		a.Tracker().SetTotalResources(len(apiMesh))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting AppMesh mesh...")
	return concurrency.Adapt(apiMesh, a.RootAdapter, a.adaptMesh), nil

}

func (a *adapter) adaptMesh(meshref appmeshTypes.MeshRef) (*appmesh.Mesh, error) {
	metadata := a.CreateMetadataFromARN(*meshref.Arn)
	mesh, err := a.client.DescribeMesh(a.Context(), &appmeshApi.DescribeMeshInput{
		MeshName: meshref.MeshName,
	})
	if err != nil {
		return nil, err
	}

	var eftype string
	if mesh.Mesh.Spec != nil {
		if mesh.Mesh.Spec.EgressFilter != nil {
			eftype = string(mesh.Mesh.Spec.EgressFilter.Type)
		}
	}

	return &appmesh.Mesh{
		Metadata: metadata,
		Spec: appmesh.Spec{
			Metadata: metadata,
			EgressFilter: appmesh.EgressFilter{
				Metadata: metadata,
				Type:     defsecTypes.String(eftype, metadata),
			},
		},
	}, nil
}

// func (a *adapter) getvirtualgateways() (apigateway []appmesh.VirtualGateway, err error) {
// 	a.Tracker().SetServiceLabel("Discovering AppMesh virtualgateways...")
// 	var apiVG []appmeshTypes.VirtualGatewayRef
// 	input = &appmeshApi.ListGatewayRoutesInput{
//        MeshName: ,
// 	}
// 	for {
// 		output, err := a.client.ListVirtualGateways(a.Context(), input)
// 		if err != nil {
// 			return nil, err
// 		}
// 		apiVG = append(apiVG, output.VirtualGateways...)
// 		a.Tracker().SetTotalResources(len(apiVG))
// 		if output.NextToken == nil {
// 			break
// 		}
// 		input.NextToken = output.NextToken
// 	}

// 	a.Tracker().SetServiceLabel("Adapting AppMesh virtualgateway...")
// 	return concurrency.Adapt(apiVG, a.RootAdapter, a.adaptVirtualGateway), nil

// }

// func (a *adapter) adaptVirtualGateway(VGref appmeshTypes.VirtualGatewayRef) (*appmesh.VirtualGateway, error) {
// 	metadata := a.CreateMetadataFromARN(*VGref.Arn)
// 	VG, err := a.client.DescribeVirtualGateway(a.Context(), &appmeshApi.DescribeVirtualGatewayInput{
// 		MeshName: VGref.MeshName,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}

// 	var path string
// 	if VG.VirtualGateway.Spec != nil {
// 		if VG.VirtualGateway.Spec.Logging != nil {
// 			if VG.VirtualGateway.Spec.Logging.AccessLog != nil {
// 				if VG.VirtualGateway.Spec.Logging.AccessLog.File.Path != nil {
// 					path = VG.VirtualGateway.Spec.Logging.AccessLog.File.Path
// 				}
// 			}
// 		}
// 	}

// 	return &appmesh.VirtualGateway{
// 		Metadata: metadata,
// 		Spec: appmesh.VGSpec{
// 			Metadata: metadata,
// 			Logging: appmesh.Logging{
// 				Metadata: metadata,
// 				AccessLog: appmesh.AccessLog{
// 					Metadata: metadata,
// 					File: appmesh.File{
// 						Metadata: metadata,
// 						Path:     defsecTypes.String("", metadata),
// 					},
// 				},
// 			},
// 		},
// 	}, nil

// }
