package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm/parser/armjson"

	"github.com/aquasecurity/defsec/pkg/scanners/azure"
)

type Parser struct {
	targetFS     fs.FS
	source       string
	debugWriter  io.Writer
	skipRequired bool
}

func (p *Parser) debug(format string, args ...interface{}) {
	if p.debugWriter == nil {
		return
	}
	_, _ = fmt.Fprintf(p.debugWriter, format, args...)
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debugWriter = writer
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(targetFS fs.FS, source string, opts ...options.ParserOption) *Parser {
	p := &Parser{
		targetFS: targetFS,
		source:   source,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, dir string) ([]*azure.Deployment, error) {

	var deployments []*azure.Deployment

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
		deployment, err := p.Parse(ctx, f, path)
		if err != nil {
			return err
		}
		deployments = append(deployments, deployment)
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
	if err := armjson.Unmarshal(data, &template); err != nil {
		p.debug("Error scanning %s: %s", path, err)
		return false
	}

	if template.Schema.Type != TypeString {
		return false
	}

	return strings.HasPrefix(template.Schema.Raw.(string), "https://schema.management.azure.com")
}

func (p *Parser) Parse(ctx context.Context, r io.Reader, filename string) (*azure.Deployment, error) {
	var template Template
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := armjson.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	return p.convertTemplate(template, filename), nil
}

func (p *Parser) convertTemplate(template Template, filename string) *azure.Deployment {
	rootMetadata := p.createMetadata(filename, 0, 0, "")
	deployment := azure.Deployment{
		Metadata:    rootMetadata,
		TargetScope: azure.ScopeResourceGroup, // TODO: override from json
		Parameters:  nil,
		Variables:   nil,
		Resources:   nil,
		Outputs:     nil,
	}

	var resolver azure.Resolver

	// TODO: the references passed here should probably not be the name - maybe params.NAME.DefaultValue?
	for name, param := range template.Parameters {
		deployment.Parameters = append(deployment.Parameters, azure.Parameter{
			Variable: azure.Variable{
				Name:  name,
				Value: azure.NewValue(param.DefaultValue.Raw, p.createParentedMetadata(rootMetadata, param.DefaultValue.StartLine, param.DefaultValue.EndLine, name), resolver),
			},
			Default:    azure.NewValue(param.DefaultValue.Raw, p.createParentedMetadata(rootMetadata, param.DefaultValue.StartLine, param.DefaultValue.EndLine, name), resolver),
			Decorators: nil,
		})
	}

	for name, variable := range template.Variables {
		deployment.Variables = append(deployment.Variables, azure.Variable{
			Name:  name,
			Value: azure.NewValue(variable.Raw, p.createParentedMetadata(rootMetadata, variable.StartLine, variable.EndLine, name), resolver),
		})
	}

	for name, output := range template.Outputs {
		deployment.Outputs = append(deployment.Outputs, azure.Output{
			Name:  name,
			Value: azure.NewValue(output.Raw, p.createParentedMetadata(rootMetadata, output.StartLine, output.EndLine, name), resolver),
		})
	}

	for _, resource := range template.Resources {
		deployment.Resources = append(deployment.Resources, p.convertResource(resource, rootMetadata, resolver))
	}

	return &deployment
}

func (p *Parser) createMetadata(filename string, start, end int, ref string) types.Metadata {
	return types.NewMetadata(
		types.NewRange(
			filename,
			start,
			end,
			"",
			p.targetFS,
		), types.NewNamedReference(ref))
}

func (p *Parser) createParentedMetadata(parent types.Metadata, start, end int, ref string) types.Metadata {

	if p := parent.Reference().String(); p != "" {
		ref = p + "." + ref
	}

	return types.NewMetadata(
		types.NewRange(
			parent.Range().GetFilename(),
			start,
			end,
			"",
			p.targetFS,
		),
		types.NewNamedReference(ref),
	).WithParent(parent)
}

func (p *Parser) convertResource(input Resource, rootMetadata types.Metadata, resolver azure.Resolver) azure.Resource {

	var name string
	if input.Name.Type == TypeString {
		name = input.Name.Raw.(string)
	}

	var properties azure.PropertyBag

	metadata := p.createParentedMetadata(rootMetadata, input.StartLine, input.EndLine, name)

	resource := azure.Resource{
		Metadata:   metadata,
		APIVersion: azure.NewValue(input.APIVersion.Raw, p.createParentedMetadata(metadata, input.APIVersion.StartLine, input.APIVersion.EndLine, "apiVersion"), resolver),
		Type:       azure.NewValue(input.Type.Raw, p.createParentedMetadata(metadata, input.Type.StartLine, input.Type.EndLine, "type"), resolver),
		Kind:       azure.NewValue(input.Kind.Raw, p.createParentedMetadata(metadata, input.Kind.StartLine, input.Kind.EndLine, "kind"), resolver),
		Name:       azure.NewValue(input.Name.Raw, p.createParentedMetadata(metadata, input.Name.StartLine, input.Name.EndLine, "name"), resolver),
		Location:   azure.NewValue(input.Location.Raw, p.createParentedMetadata(metadata, input.Location.StartLine, input.Location.EndLine, "location"), resolver),
		Properties: properties,
	}

	return resource
}
