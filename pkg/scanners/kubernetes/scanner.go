package kubernetes

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	debugWriter      io.Writer
	traceWriter      io.Writer
	policyDirs       []string
	policyReaders    []io.Reader
	dataDirs         []string
	policyNamespaces []string
	regoScanner      *rego.Scanner
	parser           *parser.Parser
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
	prefix := "[debug:scan:kubernetes] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
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
	if err := regoScanner.LoadPolicies(len(s.policyDirs)+len(s.policyReaders) == 0, srcFS, s.policyDirs, s.policyReaders); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanReader(ctx context.Context, filename string, reader io.Reader) (scan.Results, error) {
	memfs := memoryfs.New()
	if err := memfs.MkdirAll(filepath.Base(filename), 0o700); err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if err := memfs.WriteFile(filename, data, 0o644); err != nil {
		return nil, err
	}
	return s.ScanFS(ctx, memfs, ".")
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {

	k8sFiles, err := s.parser.ParseFS(ctx, target, dir)
	if err != nil {
		return nil, err
	}

	if len(k8sFiles) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for path, content := range k8sFiles {
		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: content,
			Type:     types.SourceKubernetes,
		})
	}

	regoScanner, err := s.initRegoScanner(target)
	if err != nil {
		return nil, err
	}

	s.debug("Scanning %d files...", len(inputs))
	results, err := regoScanner.ScanInput(ctx, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", target)
	return results, nil
}
