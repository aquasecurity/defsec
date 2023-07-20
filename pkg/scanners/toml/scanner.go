package toml

import (
	"context"
	"io"
	"io/fs"
	"sync"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/framework"

	"github.com/aquasecurity/defsec/pkg/debug"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/toml/parser"
)

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	debug         debug.Logger
	options       []options.ScannerOption
	policyDirs    []string
	policyReaders []io.Reader
	parser        *parser.Parser
	regoScanner   *rego.Scanner
	skipRequired  bool
	sync.Mutex
	frameworks            []framework.Framework
	spec                  string
	loadEmbeddedPolicies  bool
	loadEmbeddedLibraries bool
}

func (s *Scanner) SetRegoOnly(bool) {}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) Name() string {
	return "TOML"
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.skipRequired = skip
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "toml", "scanner")
}

func (s *Scanner) SetTraceWriter(_ io.Writer)        {}
func (s *Scanner) SetPerResultTracingEnabled(_ bool) {}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetDataDirs(_ ...string)         {}
func (s *Scanner) SetPolicyNamespaces(_ ...string) {}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

func (s *Scanner) SetDataFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}
func (s *Scanner) SetRegoErrorLimit(_ int) {}

func NewScanner(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.parser = parser.New(options.ParserWithSkipRequiredCheck(s.skipRequired))
	return s
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
	for path, file := range files {
		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: file,
			FS:       fs,
		})
	}

	results, err := s.scanRego(ctx, fs, inputs...)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {
	parsed, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}
	s.debug.Log("Scanning %s...", path)
	return s.scanRego(ctx, fs, rego.Input{
		Path:     path,
		Contents: parsed,
	})
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(types.SourceTOML, s.options...)
	regoScanner.SetParentDebugLogger(s.debug)
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, srcFS, s.policyDirs, s.policyReaders); err != nil {
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
	results.SetSourceAndFilesystem("", srcFS, false)
	return results, nil
}
