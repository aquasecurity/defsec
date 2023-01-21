package rego

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/util"

	"github.com/aquasecurity/defsec/pkg/types"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/providers"

	"github.com/open-policy-agent/opa/rego"

	"github.com/open-policy-agent/opa/ast"
)

type StaticMetadata struct {
	ID                 string
	AVDID              string
	Title              string
	ShortCode          string
	Description        string
	Severity           string
	RecommendedActions string
	PrimaryURL         string
	References         []string
	InputOptions       InputOptions
	Package            string
	Frameworks         map[framework.Framework][]string
	Provider           string
	Service            string
	Library            bool
	CloudFormation     *scan.EngineMetadata
	Terraform          *scan.EngineMetadata
}

type InputOptions struct {
	Combined  bool
	Selectors []Selector
}

type Selector struct {
	Type string
}

func (m StaticMetadata) ToRule() scan.Rule {

	provider := "generic"
	if m.Provider != "" {
		provider = m.Provider
	} else if len(m.InputOptions.Selectors) > 0 {
		provider = m.InputOptions.Selectors[0].Type
	}
	service := "general"
	if m.Service != "" {
		service = m.Service
	}

	return scan.Rule{
		AVDID:          m.AVDID,
		Aliases:        []string{m.ID},
		ShortCode:      m.ShortCode,
		Summary:        m.Title,
		Explanation:    m.Description,
		Impact:         "",
		Resolution:     m.RecommendedActions,
		Provider:       providers.Provider(provider),
		Service:        service,
		Links:          m.References,
		Severity:       severity.Severity(m.Severity),
		RegoPackage:    m.Package,
		Frameworks:     m.Frameworks,
		CloudFormation: m.CloudFormation,
		Terraform:      m.Terraform,
	}
}

type MetadataRetriever struct {
	compiler *ast.Compiler
}

func NewMetadataRetriever(compiler *ast.Compiler) *MetadataRetriever {
	return &MetadataRetriever{
		compiler: compiler,
	}
}

func (m *MetadataRetriever) findPackageAnnotation(module *ast.Module) *ast.Annotations {
	annotationSet := m.compiler.GetAnnotationSet()
	if annotationSet == nil {
		return nil
	}
	for _, annotation := range annotationSet.Flatten() {
		if annotation.GetPackage().Path.String() != module.Package.Path.String() || annotation.Annotations.Scope != "package" {
			continue
		}
		return annotation.Annotations
	}
	return nil
}

func (m *MetadataRetriever) RetrieveMetadata(ctx context.Context, module *ast.Module, inputs ...Input) (*StaticMetadata, error) {

	metadata := StaticMetadata{
		ID:           "N/A",
		Title:        "N/A",
		Severity:     "UNKNOWN",
		Description:  fmt.Sprintf("Rego module: %s", module.Package.Path.String()),
		Package:      module.Package.Path.String(),
		InputOptions: m.queryInputOptions(ctx, module),
		Frameworks:   make(map[framework.Framework][]string),
	}

	// read metadata from official rego annotations if possible
	if annotation := m.findPackageAnnotation(module); annotation != nil {
		if err := m.fromAnnotation(&metadata, annotation); err != nil {
			return nil, err
		}
		return &metadata, nil
	}

	// otherwise, try to read metadata from the rego module itself - we used to do this before annotations were a thing
	namespace := getModuleNamespace(module)
	metadataQuery := fmt.Sprintf("data.%s.__rego_metadata__", namespace)

	options := []func(*rego.Rego){
		rego.Query(metadataQuery),
		rego.Compiler(m.compiler),
		rego.Capabilities(nil),
	}
	// support dynamic metadata fields
	for _, in := range inputs {
		options = append(options, rego.Input(in.Contents))
	}

	instance := rego.New(options...)
	set, err := instance.Eval(ctx)
	if err != nil {
		return nil, err
	}

	// no metadata supplied
	if set == nil {
		return &metadata, nil
	}

	if len(set) != 1 {
		return nil, fmt.Errorf("failed to parse metadata: unexpected set length")
	}
	if len(set[0].Expressions) != 1 {
		return nil, fmt.Errorf("failed to parse metadata: unexpected expression length")
	}
	expression := set[0].Expressions[0]
	meta, ok := expression.Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse metadata: not an object")
	}

	err = m.updateMetadata(meta, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// nolint
func (m *MetadataRetriever) updateMetadata(meta map[string]interface{}, metadata *StaticMetadata) error {
	if raw, ok := meta["id"]; ok {
		metadata.ID = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["avd_id"]; ok {
		metadata.AVDID = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["title"]; ok {
		metadata.Title = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["short_code"]; ok {
		metadata.ShortCode = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["severity"]; ok {
		metadata.Severity = strings.ToUpper(fmt.Sprintf("%s", raw))
	}
	if raw, ok := meta["description"]; ok {
		metadata.Description = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["service"]; ok {
		metadata.Service = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["provider"]; ok {
		metadata.Provider = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["library"]; ok {
		if lib, ok := raw.(bool); ok {
			metadata.Library = lib
		}
	}
	if raw, ok := meta["recommended_actions"]; ok {
		metadata.RecommendedActions = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["recommended_action"]; ok {
		metadata.RecommendedActions = fmt.Sprintf("%s", raw)
	}
	if raw, ok := meta["url"]; ok {
		metadata.References = append(metadata.References, fmt.Sprintf("%s", raw))
	}
	if raw, ok := meta["frameworks"]; ok {
		frameworks, ok := raw.(map[string][]string)
		if !ok {
			return fmt.Errorf("failed to parse framework metadata: not an object")
		}
		for fw, sections := range frameworks {
			metadata.Frameworks[framework.Framework(fw)] = sections
		}
	}
	if raw, ok := meta["related_resources"]; ok {
		if relatedResources, ok := raw.([]interface{}); ok {
			for _, relatedResource := range relatedResources {
				if relatedResourceMap, ok := relatedResource.(map[string]interface{}); ok {
					if raw, ok := relatedResourceMap["ref"]; ok {
						metadata.References = append(metadata.References, fmt.Sprintf("%s", raw))
					}
				} else if relatedResourceString, ok := relatedResource.(string); ok {
					metadata.References = append(metadata.References, fmt.Sprintf("%s", relatedResourceString))
				}
			}
		}
	}

	var err error
	if metadata.CloudFormation, err = m.getEngineMetadata("cloud_formation", meta); err != nil {
		return err
	}

	if metadata.Terraform, err = m.getEngineMetadata("terraform", meta); err != nil {
		return err
	}

	return nil
}

func (m *MetadataRetriever) getEngineMetadata(schema string, meta map[string]interface{}) (*scan.EngineMetadata, error) {
	var sMap map[string]interface{}
	if raw, ok := meta[schema]; ok {
		sMap, ok = raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse %s metadata: not an object", schema)
		}
	}

	var em scan.EngineMetadata
	if val, ok := sMap["good_examples"].(string); ok {
		em.GoodExamples = []string{val}
	}
	if val, ok := sMap["bad_examples"].(string); ok {
		em.BadExamples = []string{val}
	}
	if val, ok := sMap["links"].(string); ok {
		em.Links = []string{val}
	}
	if val, ok := sMap["remediation_markdown"].(string); ok {
		em.RemediationMarkdown = val
	}

	return &em, nil
}

func (m *MetadataRetriever) fromAnnotation(metadata *StaticMetadata, annotation *ast.Annotations) error {
	metadata.Title = annotation.Title
	metadata.Description = annotation.Description
	for _, resource := range annotation.RelatedResources {
		if !resource.Ref.IsAbs() {
			continue
		}
		metadata.References = append(metadata.References, resource.Ref.String())
	}
	if custom := annotation.Custom; custom != nil {
		if err := m.updateMetadata(custom, metadata); err != nil {
			return err
		}
	}
	if len(annotation.RelatedResources) > 0 {
		metadata.PrimaryURL = annotation.RelatedResources[0].Ref.String()
	}
	return nil
}

func (m *MetadataRetriever) queryInputOptions(ctx context.Context, module *ast.Module) InputOptions {

	options := InputOptions{
		Combined:  false,
		Selectors: nil,
	}

	var metadata map[string]interface{}

	// read metadata from official rego annotations if possible
	if annotation := m.findPackageAnnotation(module); annotation != nil && annotation.Custom != nil {
		if input, ok := annotation.Custom["input"]; ok {
			if mapped, ok := input.(map[string]interface{}); ok {
				metadata = mapped
			}
		}
	}

	if metadata == nil {

		namespace := getModuleNamespace(module)
		inputOptionQuery := fmt.Sprintf("data.%s.__rego_input__", namespace)
		instance := rego.New(
			rego.Query(inputOptionQuery),
			rego.Compiler(m.compiler),
			rego.Capabilities(nil),
		)
		set, err := instance.Eval(ctx)
		if err != nil {
			return options
		}

		if len(set) != 1 {
			return options
		}
		if len(set[0].Expressions) != 1 {
			return options
		}
		expression := set[0].Expressions[0]
		meta, ok := expression.Value.(map[string]interface{})
		if !ok {
			return options
		}
		metadata = meta
	}

	if raw, ok := metadata["combine"]; ok {
		if combine, ok := raw.(bool); ok {
			options.Combined = combine
		}
	}

	if raw, ok := metadata["selector"]; ok {
		if each, ok := raw.([]interface{}); ok {
			for _, rawSelector := range each {
				var selector Selector
				if selectorMap, ok := rawSelector.(map[string]interface{}); ok {
					if rawType, ok := selectorMap["type"]; ok {
						selector.Type = fmt.Sprintf("%s", rawType)
						// handle backward compatibility for "defsec" source type which is now "cloud"
						if selector.Type == string(types.SourceDefsec) {
							selector.Type = string(types.SourceCloud)
						}
					}
				}
				options.Selectors = append(options.Selectors, selector)
			}
		}
	}

	return options

}

func BuildSchemaSetFromPolicies(policies map[string]*ast.Module, logger func(format string, args ...interface{})) (*ast.SchemaSet, bool) {
	schemaSet := ast.NewSchemaSet()
	schemaSet.Put(ast.MustParseRef("schema.input"), map[string]interface{}{}) // for backwards compat only
	var customFound bool
	for name, policy := range policies {
		for _, annotation := range policy.Annotations {
			for _, schemas := range annotation.Schemas {
				schemaName, err := schemas.Schema.Ptr()
				if err != nil {
					continue
				}
				if schemaName != "input" {
					if logger != nil {
						logger("Detected schema type: %s, for policy: %s", schemaName, name)
					}
					customFound = true
					if schema, ok := SchemaMap[defsecTypes.Source(schemaName)]; ok {
						schemaSet.Put(ast.MustParseRef(schemas.Schema.String()), util.MustUnmarshalJSON([]byte(schema)))
					}
				}
			}
		}
	}

	return schemaSet, customFound
}
