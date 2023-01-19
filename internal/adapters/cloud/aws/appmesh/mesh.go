package appmesh

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	appmeshApi "github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmeshTypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/aws/aws-sdk-go/aws"
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
	response, err := a.client.DescribeMesh(a.Context(), &appmeshApi.DescribeMeshInput{
		MeshName: meshref.MeshName,
	})
	if err != nil {
		return nil, err
	}

	var eftype string
	if response.Mesh.Spec != nil {
		if response.Mesh.Spec.EgressFilter != nil {
			eftype = string(response.Mesh.Spec.EgressFilter.Type)
		}
	}

	var virtualgateways []appmesh.VirtualGateway
	output, err := a.client.ListVirtualGateways(a.Context(), &appmeshApi.ListVirtualGatewaysInput{
		MeshName: meshref.MeshName,
	})
	if err != nil {
		return nil, err
	}

	for _, VG := range output.VirtualGateways {
		VGresponse, err := a.client.DescribeVirtualGateway(a.Context(), &appmeshApi.DescribeVirtualGatewayInput{
			VirtualGatewayName: aws.String(*VG.VirtualGatewayName),
			MeshName:           aws.String(*meshref.MeshName),
		})
		if err != nil {
			return nil, err
		}

		// var accessLogFilePath string
		// if  VGresponse.VirtualGateway.Spec.Logging.AccessLog != nil{
		// 	accesslog := VGresponse.VirtualGateway.Spec.Logging.AccessLog
		// 	accesslog = *accesslog.
		// }

		var listeners []appmesh.Listener
		for _, listener := range VGresponse.VirtualGateway.Spec.Listeners {
			var tlsmode string
			if listener.Tls != nil {
				tlsmode = string(listener.Tls.Mode)
			}

			listeners = append(listeners, appmesh.Listener{
				Metadata: metadata,
				TLS: appmesh.TLS{
					Metadata: metadata,
					Mode:     defsecTypes.String(tlsmode, metadata),
				},
			})
		}

		virtualgateways = append(virtualgateways, appmesh.VirtualGateway{
			Metadata: metadata,
			Spec: appmesh.VGSpec{
				Metadata: metadata,
				Logging: appmesh.Logging{
					Metadata: metadata,
					//AccessLogFilePath: accessLogFilePath,
				},
				Listeners: listeners,
			},
		})
	}

	return &appmesh.Mesh{
		Metadata: metadata,
		Name:     defsecTypes.String(*meshref.MeshName, metadata),
		Spec: appmesh.Spec{
			Metadata: metadata,
			EgressFilter: appmesh.EgressFilter{
				Metadata: metadata,
				Type:     defsecTypes.String(eftype, metadata),
			},
		},
		VirtualGateways: virtualgateways,
	}, nil
}
