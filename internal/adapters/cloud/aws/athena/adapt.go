package athena

import (
	"fmt"

	defsecTypes "github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "athena"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Athena.Workgroups, err = a.getWorkgroups()
	if err != nil {
		return err
	}

	state.AWS.Athena.Databases, err = a.getDatabases()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getWorkgroups() ([]athena.Workgroup, error) {

	a.Tracker().SetServiceLabel("Discovering workgroups...")

	var apiWorkgroups []types.WorkGroupSummary
	var input api.ListWorkGroupsInput
	for {
		output, err := a.client.ListWorkGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiWorkgroups = append(apiWorkgroups, output.WorkGroups...)
		a.Tracker().SetTotalResources(len(apiWorkgroups))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting workgroups...")

	var workgroups []athena.Workgroup
	for _, apiWorkgroup := range apiWorkgroups {
		workgroup, err := a.adaptWorkgroup(apiWorkgroup)
		if err != nil {
			a.Debug("Failed to adapt workgroup '%s': %s", workgroup.Name, err)
			continue
		}
		workgroups = append(workgroups, *workgroup)
		a.Tracker().IncrementResource()
	}
	return workgroups, nil
}

func (a *adapter) adaptWorkgroup(workgroup types.WorkGroupSummary) (*athena.Workgroup, error) {
	metadata := a.CreateMetadata(fmt.Sprintf("workgroup/%s", *workgroup.Name))

	output, err := a.client.GetWorkGroup(a.Context(), &api.GetWorkGroupInput{
		WorkGroup: workgroup.Name,
	})
	if err != nil {
		return nil, err
	}

	var enforce bool
	var encType string
	if config := output.WorkGroup.Configuration; config != nil {
		if config.EnforceWorkGroupConfiguration != nil {
			enforce = *config.EnforceWorkGroupConfiguration
		}
		if resultConfig := config.ResultConfiguration; resultConfig != nil {
			if resultConfig.EncryptionConfiguration != nil {
				encType = string(resultConfig.EncryptionConfiguration.EncryptionOption)
			}
		}

	}

	return &athena.Workgroup{
		Metadata: metadata,
		Name:     defsecTypes.String(*workgroup.Name, metadata),
		Encryption: athena.EncryptionConfiguration{
			Metadata: metadata,
			Type:     defsecTypes.String(encType, metadata),
		},
		EnforceConfiguration: defsecTypes.Bool(enforce, metadata),
	}, nil
}

func (a *adapter) getDatabases() ([]athena.Database, error) {

	a.Tracker().SetServiceLabel("Discovering catalogues...")

	var apiCatalogues []types.DataCatalogSummary
	var input api.ListDataCatalogsInput
	for {
		output, err := a.client.ListDataCatalogs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiCatalogues = append(apiCatalogues, output.DataCatalogsSummary...)
		a.Tracker().SetTotalResources(len(apiCatalogues))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting catalogues...")

	var databases []athena.Database

	for _, apiCatalogue := range apiCatalogues {
		catalogueDatabases, err := a.getDatabasesForCatalogue(*apiCatalogue.CatalogName)
		if err != nil {
			return nil, err
		}
		databases = append(databases, catalogueDatabases...)
		a.Tracker().IncrementResource()
	}
	return databases, nil
}

func (a *adapter) getDatabasesForCatalogue(catalogueName string) ([]athena.Database, error) {

	var apiDatabases []types.Database
	input := api.ListDatabasesInput{
		CatalogName: &catalogueName,
	}
	for {
		output, err := a.client.ListDatabases(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDatabases = append(apiDatabases, output.DatabaseList...)
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	var databases []athena.Database
	for _, apiDatabase := range apiDatabases {
		catalogue, err := a.adaptDatabase(apiDatabase)
		if err != nil {
			a.Debug("Failed to adapt database '%s': %s", *apiDatabase.Name, err)
			continue
		}
		databases = append(databases, *catalogue)
	}
	return databases, nil
}

func (a *adapter) adaptDatabase(database types.Database) (*athena.Database, error) {
	metadata := a.CreateMetadata("database/" + *database.Name)
	return &athena.Database{
		Metadata: metadata,
		Name:     defsecTypes.String(*database.Name, metadata),
		Encryption: athena.EncryptionConfiguration{
			Metadata: metadata,
			// see https://stackoverflow.com/questions/72456689/what-does-encryption-configuration-in-terraform-aws-athena-database-resource
			Type: defsecTypes.String("", defsecTypes.NewUnmanagedMetadata()),
		},
	}, nil
}
