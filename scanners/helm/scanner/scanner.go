package scanner

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/defsec/parsers/helm/parser"
	kparser "github.com/aquasecurity/defsec/parsers/kubernetes/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/rego"
	"github.com/aquasecurity/defsec/rules"
)

type Scanner struct {
	chartName   string
	policyDirs  []string
	dataDirs    []string
	paths       []string
	debugWriter io.Writer
}

// New creates a new Scanner
func New(chartName string, options ...Option) *Scanner {
	s := &Scanner{
		chartName: chartName,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) AddPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	s.paths = append(s.paths, path)
	return nil
}

func (s *Scanner) Scan() (rules.Results, error) {

	var results []rules.Result
	parser := parser.New(s.chartName)

	// add paths for parsing
	if err := parser.AddPaths(s.paths...); err != nil {
		return nil, fmt.Errorf("file add: %w", err)
	}

	chartFiles, err := parser.RenderedChartFiles()
	if err != nil {
		return nil, err
	}

	regoScanner := rego.NewScanner()
	if err := regoScanner.LoadPolicies(true); err != nil {
		return nil, fmt.Errorf("policies load: %w", err)
	}
	for _, file := range chartFiles {
		s.debug("Processing rendered chart file: %s", file.TemplateFilePath)

		manifest, err := kparser.New().Parse(file.TemplateFilePath, file.ManifestContent)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		fileResults, err := regoScanner.ScanInput(context.Background(), rego.Input{
			Path:     file.TemplateFilePath,
			Contents: manifest.ToRegoMap(),
			Type:     types.SourceKubernetes,
		})
		if err != nil {
			fmt.Println(err)
			//return nil, fmt.Errorf("scanning error: %w", err)
		}
		results = append(results, fileResults...)
	}

	return results, nil

}
