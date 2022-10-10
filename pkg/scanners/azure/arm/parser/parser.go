package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/scanners/azure"
	"github.com/aquasecurity/defsec/pkg/scanners/azure/resolver"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm/parser/armjson"
)

type Parser struct {
	targetFS     fs.FS
	skipRequired bool
	debug        debug.Logger
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "azure", "arm")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(targetFS fs.FS, opts ...options.ParserOption) *Parser {
	p := &Parser{
		targetFS: targetFS,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, dir string) ([]azure.Deployment, error) {

	var deployments []azure.Deployment

	if err := fs.WalkDir(p.targetFS, dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			return nil
		}
		if !p.Required(path) {
			return nil
		}
		f, err := p.targetFS.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		deployment, err := p.parseFile(f, path)
		if err != nil {
			return err
		}
		deployments = append(deployments, *deployment)
		return nil
	}); err != nil {
		return nil, err
	}

	return deployments, nil
}

func (p *Parser) Required(path string) bool {
	if p.skipRequired {
		return true
	}
	if !strings.HasSuffix(path, ".json") {
		return false
	}
	data, err := fs.ReadFile(p.targetFS, path)
	if err != nil {
		return false
	}
	var template Template
	root := types.NewMetadata(
		types.NewRange(filepath.Base(path), 0, 0, "", p.targetFS),
		"",
	)
	if err := armjson.Unmarshal(data, &template, &root); err != nil {
		p.debug.Log("Error scanning %s: %s", path, err)
		return false
	}

	if template.Schema.Kind != azure.KindString {
		return false
	}

	return strings.HasPrefix(template.Schema.AsString(), "https://schema.management.azure.com")
}

func (p *Parser) parseFile(r io.Reader, filename string) (*azure.Deployment, error) {
	var template Template
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	root := types.NewMetadata(
		types.NewRange(filename, 0, 0, "", p.targetFS),
		"",
	).WithInternal(resolver.NewResolver())

	if err := armjson.Unmarshal(data, &template, &root); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	return p.convertTemplate(template), nil
}

func (p *Parser) convertTemplate(template Template) *azure.Deployment {

	deployment := azure.Deployment{
		Metadata:    template.Metadata,
		TargetScope: azure.ScopeResourceGroup, // TODO: override from --resource-group?
		Parameters:  nil,
		Variables:   nil,
		Resources:   nil,
		Outputs:     nil,
	}

	if r, ok := template.Metadata.Internal().(resolver.Resolver); ok {
		r.SetDeployment(&deployment)
	}

	// TODO: the references passed here should probably not be the name - maybe params.NAME.DefaultValue?
	for name, param := range template.Parameters {
		deployment.Parameters = append(deployment.Parameters, azure.Parameter{
			Variable: azure.Variable{
				Name:  name,
				Value: param.DefaultValue,
			},
			Default:    param.DefaultValue,
			Decorators: nil,
		})
	}

	for name, variable := range template.Variables {
		deployment.Variables = append(deployment.Variables, azure.Variable{
			Name:  name,
			Value: variable,
		})
	}

	for name, output := range template.Outputs {
		deployment.Outputs = append(deployment.Outputs, azure.Output{
			Name:  name,
			Value: output,
		})
	}

	for _, resource := range template.Resources {
		deployment.Resources = append(deployment.Resources, p.convertResource(resource))
	}

	return &deployment
}

func (p *Parser) convertResource(input Resource) azure.Resource {

	var children []azure.Resource

	for _, child := range input.Resources {
		children = append(children, p.convertResource(child))
	}

	resource := azure.Resource{
		Metadata:   input.Metadata,
		APIVersion: input.APIVersion,
		Type:       input.Type,
		Kind:       input.Kind,
		Name:       input.Name,
		Location:   input.Location,
		Properties: input.Properties,
		Resources:  children,
	}

	return resource
}
