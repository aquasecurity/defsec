package accessanalyzer

import "github.com/aquasecurity/defsec/pkg/types"

type AccessAnalyzer struct {
	Analyzers []Analyzer
}

type Analyzer struct {
	Metadata types.Metadata
	ARN      types.StringValue
	Name     types.StringValue
	Active   types.BoolValue
}
