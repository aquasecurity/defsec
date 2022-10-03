package arm

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/arm/appservice"
	"github.com/aquasecurity/defsec/internal/adapters/arm/authorization"
	"github.com/aquasecurity/defsec/internal/adapters/arm/compute"
	"github.com/aquasecurity/defsec/internal/adapters/arm/container"
	"github.com/aquasecurity/defsec/internal/adapters/arm/database"
	"github.com/aquasecurity/defsec/internal/adapters/arm/datafactory"
	"github.com/aquasecurity/defsec/internal/adapters/arm/datalake"
	"github.com/aquasecurity/defsec/internal/adapters/arm/keyvault"
	"github.com/aquasecurity/defsec/internal/adapters/arm/monitor"
	"github.com/aquasecurity/defsec/internal/adapters/arm/network"
	"github.com/aquasecurity/defsec/internal/adapters/arm/securitycenter"
	"github.com/aquasecurity/defsec/internal/adapters/arm/storage"
	"github.com/aquasecurity/defsec/internal/adapters/arm/synapse"

	"github.com/aquasecurity/defsec/pkg/providers/azure"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/azure"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(ctx context.Context, deployment scanner.Deployment) *state.State {
	return &state.State{
		Azure: adaptAzure(deployment),
	}
}

func adaptAzure(deployment scanner.Deployment) azure.Azure {

	return azure.Azure{
		AppService:     appservice.Adapt(deployment),
		Authorization:  authorization.Adapt(deployment),
		Compute:        compute.Adapt(deployment),
		Container:      container.Adapt(deployment),
		Database:       database.Adapt(deployment),
		DataFactory:    datafactory.Adapt(deployment),
		DataLake:       datalake.Adapt(deployment),
		KeyVault:       keyvault.Adapt(deployment),
		Monitor:        monitor.Adapt(deployment),
		Network:        network.Adapt(deployment),
		SecurityCenter: securitycenter.Adapt(deployment),
		Storage:        storage.Adapt(deployment),
		Synapse:        synapse.Adapt(deployment),
	}

}
