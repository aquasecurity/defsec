package compute

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/azure"
	"github.com/aquasecurity/defsec/pkg/providers/azure/compute"
	"github.com/aquasecurity/defsec/pkg/state"
	"net/http"
	"os"
)

type adapter struct {
	*azure.RootAdapter
}

func init() {
	azure.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "azure"
}

func (a *adapter) Name() string {
	return "compute"
}

func (a *adapter) Adapt(root *azure.RootAdapter, state *state.State) error {

	a.RootAdapter = root

	var err error
	state.Azure.Compute.VirtualMachineList, err = a.adaptVirtualMachine()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) adaptVirtualMachine() (compute.VirtualMachineList, error) {
	apiURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01", "26a1a07e-06dd-4892-92c9-e4996b0fc546")
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}

	token := azure.GetToken()
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		os.Exit(1)
	}
	defer response.Body.Close()

	var vmList compute.VirtualMachineList
	err = json.NewDecoder(response.Body).Decode(&vmList)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		os.Exit(1)
	}
	var virtualmachine []compute.VirtualMachines
	for _, vm := range vmList.Value {
		virtualmachine = append(virtualmachine, compute.VirtualMachines{
			Metadata: vm.Metadata,
			Id:       vm.Id,
			Name:     vm.Name,
			Properties: compute.Properties{
				Metadata:          vm.Properties.Metadata,
				VmId:              vm.Properties.VmId,
				ProvisioningState: vm.Properties.ProvisioningState,
				DiagnosticsProfile: compute.DiagnosticsProfile{
					BootDiagnostics: compute.BootDiagnostics{
						Metadata: vm.Properties.DiagnosticsProfile.BootDiagnostics.Metadata,
						Enabled:  vm.Properties.DiagnosticsProfile.BootDiagnostics.Enabled,
					},
				},
			},
		})

	}
	return compute.VirtualMachineList{
		Value: virtualmachine,
	}, nil
}
