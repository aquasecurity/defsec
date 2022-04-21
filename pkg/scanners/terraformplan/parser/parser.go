package parser

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/liamg/memoryfs"
)

type Parser struct {
	debugWriter    io.Writer
	stopOnHCLError bool
}

func New(options ...Option) *Parser {
	parser := &Parser{}

	for _, o := range options {
		o(parser)
	}
	return parser
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debugWriter = writer
}

func (p *Parser) SetStopOnHCLError(b bool) {
	p.stopOnHCLError = b
}

func (p *Parser) ParseFile(filepath string) (*PlanFile, error) {

	if _, err := os.Stat(filepath); err != nil {
		return nil, err
	}

	reader, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return p.Parse(reader)
}

func (p *Parser) Parse(reader io.Reader) (*PlanFile, error) {

	var planFile PlanFile

	if err := json.NewDecoder(reader).Decode(&planFile); err != nil {
		return nil, err
	}

	return &planFile, nil

}

func (p *PlanFile) ToFS() (*memoryfs.FS, error) {

	rootFS := memoryfs.New()

	var fileResources []string

	resources, err := getResources(p.PlannedValues.RootModule, p.ResourceChanges, p.Configuration)
	if err != nil {
		return nil, err
	}
	for _, r := range resources {
		fileResources = append(fileResources, r.ToHCL())
	}

	fileContent := strings.Join(fileResources, "\n\n")
	if err := rootFS.WriteFile("main.tf", []byte(fileContent), os.ModePerm); err != nil {
		return nil, err
	}

	return rootFS, nil

}

func getResources(module Module, resourceChanges []ResourceChange, configuration Configuration) ([]terraform.PlanBlock, error) {
	var resources []terraform.PlanBlock
	for _, r := range module.Resources {
		res := terraform.NewResourceBlock(r.Type, r.Name)

		changes := getValues(r.Address, resourceChanges)
		// process the changes to get the after state
		for k, v := range changes.After {
			switch t := v.(type) {
			case []interface{}:
				if len(t) == 0 {
					continue
				}
				val := t[0]
				switch v := val.(type) {
				// is it a HCL block?
				case map[string]interface{}:
					res.Blocks[k] = v
				// just a normal attribute then
				default:
					res.Attributes[k] = v
				}
			default:
				res.Attributes[k] = v
			}
		}

		resourceConfig := getConfiguration(r.Address, configuration.RootModule)
		if resourceConfig != nil {

			for attr, val := range resourceConfig.Expressions {
				if !res.HasAttribute(attr) {
					res.Attributes[attr] = unpackConfigurationValue(val)
				}
			}

		}
		resources = append(resources, *res)
	}

	for _, m := range module.ChildModules {
		cr, err := getResources(m.Module, resourceChanges, configuration)
		if err != nil {
			return nil, err
		}
		resources = append(resources, cr...)
	}

	return resources, nil
}

func unpackConfigurationValue(val interface{}) interface{} {

	switch t := val.(type) {
	case map[string]interface{}:
		for k, v := range t {
			switch k {
			case "references":
				return terraform.PlanReference{Value: v.([]interface{})[0]}
			case "constant_value":
				return v
			}
		}
	}

	return nil
}

func getConfiguration(address string, configuration ConfigurationModule) *ConfigurationResource {

	for _, resource := range configuration.Resources {
		if resource.Address == address {
			return &resource
		}
	}

	for _, childModule := range configuration.ChildModules {
		return getConfiguration(address, childModule.ConfigurationModule)
	}

	return nil
}

func getValues(address string, resourceChange []ResourceChange) *ResourceChange {
	for _, r := range resourceChange {
		if r.Address == address {
			return &r
		}
	}
	return nil
}
