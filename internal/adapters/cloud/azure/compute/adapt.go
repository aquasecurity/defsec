package compute

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/azure"
	"github.com/aquasecurity/defsec/pkg/providers/azure/compute"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"io/ioutil"
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

func (a *adapter) adaptVirtualMachine() ([]compute.VirtualMachines, error) {

	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		fmt.Println("missing environment variable AZURE_SUBSCRIPTION_ID")
		os.Exit(1)
	}

	apiURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01", subscriptionID)
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

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}

	// Unmarshal JSON data into a map[string]interface{}
	var jsonData map[string]interface{}
	err = json.Unmarshal(responseBody, &jsonData)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		os.Exit(1)
	}
	var VirtualMachine []compute.VirtualMachines

	if valueArray, ok := jsonData["value"].([]interface{}); ok {
		if len(valueArray) == 0 {
			fmt.Println("No existing virtual machines found")
			os.Exit(1)
		}
		// Loop through the array elements
		for _, element := range valueArray {
			if elemMap, ok := element.(map[string]interface{}); ok {
				// Access nested fields using type assertion
				var prop compute.Properties
				var enabled defsecTypes.BoolValue
				metadata := a.CreateMetadata(elemMap["id"].(string))
				if properties, ok := elemMap["properties"].(map[string]interface{}); ok {

					if DiagnosticProfile, ok := properties["diagnosticsProfile"].(map[string]interface{}); ok {
						if BootDiagnostics, ok := DiagnosticProfile["bootDiagnostics"].(map[string]interface{}); ok {
							enabled = defsecTypes.Bool(BootDiagnostics["enabled"].(bool), metadata)
						}
					}
					prop = compute.Properties{
						Metadata: metadata,
						VmId:     defsecTypes.String(properties["vmId"].(string), metadata),
						DiagnosticsProfile: compute.DiagnosticsProfile{
							Metadata: metadata,
							BootDiagnostics: compute.BootDiagnostics{
								Metadata: metadata,
								Enabled:  enabled,
							},
						},
					}
				}

				VirtualMachine = append(VirtualMachine, compute.VirtualMachines{
					Metadata:   metadata,
					Id:         defsecTypes.String(elemMap["id"].(string), metadata),
					Name:       defsecTypes.String(elemMap["name"].(string), metadata),
					Properties: prop,
				})
			}
		}
	}

	return VirtualMachine, nil
}
