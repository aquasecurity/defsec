package dockerfile

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"sync"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	debugWriter      io.Writer
	traceWriter      io.Writer
	policyDirs       []string
	dataDirs         []string
	policyNamespaces []string
	parser           *parser.Parser
	regoScanner      *rego.Scanner
	sync.Mutex
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

	if len(files) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for path, dfile := range files {
		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: dfile.ToRego(),
			Type:     types.SourceDockerfile,
		})
	}

	results, err := s.scanRego(ctx, fs, inputs...)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {
	dockerfile, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}
	s.debug("Scanning %s...", path)
	return s.scanRego(ctx, fs, rego.Input{
		Path:     path,
		Contents: dockerfile.ToRego(),
		Type:     types.SourceDockerfile,
	})
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoOpts := []rego.Option{
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
		rego.OptionWithDataDirs(s.dataDirs...),
	}
	if s.traceWriter != nil {
		regoOpts = append(regoOpts, rego.OptionWithTrace(s.traceWriter))
	}
	regoScanner := rego.NewScanner(regoOpts...)
	if err := regoScanner.LoadPolicies(len(s.policyDirs) == 0, srcFS, s.policyDirs, nil); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) scanRego(ctx context.Context, srcFS fs.FS, inputs ...rego.Input) (scan.Results, error) {
	regoScanner, err := s.initRegoScanner(srcFS)
	if err != nil {
		return nil, err
	}
	results, err := regoScanner.ScanInput(ctx, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", srcFS)
	return results, nil
}
