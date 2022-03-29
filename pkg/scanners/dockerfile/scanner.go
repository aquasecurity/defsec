package dockerfile

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	debugWriter      io.Writer
	policyDirs       []string
	dataDirs         []string
	policyNamespaces []string
	parser           *parser.Parser
}

func NewScanner(options ...Option) *Scanner {
	s := &Scanner{
		debugWriter: ioutil.Discard,
		parser:      parser.New(),
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:dockerfile] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {

	files, err := s.parser.ParseFS(ctx, fs, path)
	if err != nil {
		return nil, err
	}

	var inputs []rego.Input
	for path, dfile := range files {
		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: dfile.ToRego(),
			Type:     types.SourceDockerfile,
		})
	}

	return s.scanRego(ctx, inputs...)
}

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {
	dockerfile, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}
	return s.scanRego(ctx, rego.Input{
		Path:     path,
		Contents: dockerfile.ToRego(),
		Type:     types.SourceDockerfile,
	})
}

func (s *Scanner) scanRego(ctx context.Context, inputs ...rego.Input) (scan.Results, error) {
	regoScanner := rego.NewScanner(
		rego.OptionWithDebug(s.debugWriter),
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
	)
	if err := regoScanner.LoadPolicies(len(s.policyDirs) == 0, s.policyDirs...); err != nil {
		return nil, err
	}
	return regoScanner.ScanInput(ctx, inputs...)
}
