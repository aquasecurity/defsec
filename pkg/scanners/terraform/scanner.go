package terraform

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser/resolvers"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	parserOpt        []parser.Option
	executorOpt      []executor.Option
	dirs             map[string]struct{}
	forceAllDirs     bool
	debugWriter      io.Writer
	traceWriter      io.Writer
	policyDirs       []string
	dataDirs         []string
	policyNamespaces []string
	regoScanner      *rego.Scanner
	execLock         sync.RWMutex
	sync.Mutex
}

type Metrics struct {
	Parser   parser.Metrics
	Executor executor.Metrics
	Timings  struct {
		Total time.Duration
	}
}

func New(options ...Option) *Scanner {
	s := &Scanner{
		dirs:        make(map[string]struct{}),
		debugWriter: ioutil.Discard,
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
	prefix := "[debug:scan:terraform] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {
	results, _, err := s.ScanFSWithMetrics(ctx, target, dir)
	return results, err
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
	if err := regoScanner.LoadPolicies(true, srcFS, s.policyDirs, nil); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFSWithMetrics(ctx context.Context, target fs.FS, dir string) (scan.Results, Metrics, error) {

	var metrics Metrics

	// find directories which directly contain tf files (and have no parent containing tf files)
	rootDirs := s.findRootModules(target, dir)
	sort.Strings(rootDirs)

	if len(rootDirs) == 0 {
		return nil, metrics, nil
	}

	regoScanner, err := s.initRegoScanner(target)
	if err != nil {
		return nil, metrics, err
	}

	s.execLock.Lock()
	s.executorOpt = append(s.executorOpt, executor.OptionWithRegoScanner(regoScanner))
	s.execLock.Unlock()

	var allResults scan.Results

	// parse all root module directories
	for _, dir := range rootDirs {

		s.debug("Scanning root module '%s'...", dir)

		p := parser.New(target, "", s.parserOpt...)
		s.execLock.RLock()
		e := executor.New(s.executorOpt...)
		s.execLock.RUnlock()

		if err := p.ParseFS(ctx, dir); err != nil {
			return nil, metrics, err
		}

		modules, _, err := p.EvaluateAll(ctx)
		if err != nil {
			return nil, metrics, err
		}

		parserMetrics := p.Metrics()
		metrics.Parser.Counts.Blocks += parserMetrics.Counts.Blocks
		metrics.Parser.Counts.Modules += parserMetrics.Counts.Modules
		metrics.Parser.Counts.Files += parserMetrics.Counts.Files
		metrics.Parser.Timings.DiskIODuration += parserMetrics.Timings.DiskIODuration
		metrics.Parser.Timings.ParseDuration += parserMetrics.Timings.ParseDuration

		results, execMetrics, err := e.Execute(modules)
		if err != nil {
			return nil, metrics, err
		}

		metrics.Executor.Counts.Passed += execMetrics.Counts.Passed
		metrics.Executor.Counts.Failed += execMetrics.Counts.Failed
		metrics.Executor.Counts.Ignored += execMetrics.Counts.Ignored
		metrics.Executor.Counts.Critical += execMetrics.Counts.Critical
		metrics.Executor.Counts.High += execMetrics.Counts.High
		metrics.Executor.Counts.Medium += execMetrics.Counts.Medium
		metrics.Executor.Counts.Low += execMetrics.Counts.Low
		metrics.Executor.Timings.Adaptation += execMetrics.Timings.Adaptation
		metrics.Executor.Timings.RunningChecks += execMetrics.Timings.RunningChecks

		allResults = append(allResults, results...)
	}

	metrics.Parser.Counts.ModuleDownloads = resolvers.Remote.GetDownloadCount()

	metrics.Timings.Total += metrics.Parser.Timings.DiskIODuration
	metrics.Timings.Total += metrics.Parser.Timings.ParseDuration
	metrics.Timings.Total += metrics.Executor.Timings.Adaptation
	metrics.Timings.Total += metrics.Executor.Timings.RunningChecks

	allResults.SetRelativeTo(dir)
	return allResults, metrics, nil
}

func (s *Scanner) removeNestedDirs(dirs []string) []string {
	if s.forceAllDirs {
		return dirs
	}
	var clean []string
	for _, dirA := range dirs {
		dirOK := true
		for _, dirB := range dirs {
			if dirA == dirB {
				continue
			}
			if str, err := filepath.Rel(dirB, dirA); err == nil && !strings.HasPrefix(str, "..") {
				dirOK = false
				break
			}
		}
		if dirOK {
			clean = append(clean, dirA)
		}
	}
	return clean
}

func (s *Scanner) findRootModules(target fs.FS, dirs ...string) []string {

	var roots []string
	var others []string

	for _, dir := range dirs {
		if isRootModule(target, dir) {
			roots = append(roots, dir)
			if !s.forceAllDirs {
				continue
			}
		}

		// if this isn't a root module, look at directories inside it
		files, err := fs.ReadDir(target, dir)
		if err != nil {
			continue
		}
		for _, file := range files {
			realPath := filepath.Join(dir, file.Name())
			if symFS, ok := target.(extrafs.ReadLinkFS); ok {
				realPath, err = symFS.ResolveSymlink(realPath)
				if err != nil {
					s.debug("failed to resolve symlink '%s': %s", file.Name(), err)
					continue
				}
			}
			if file.IsDir() {
				others = append(others, realPath)
			} else if statFS, ok := target.(fs.StatFS); ok {
				info, err := statFS.Stat(realPath)
				if err != nil {
					continue
				}
				if info.IsDir() {
					others = append(others, realPath)
				}
			}
		}
	}

	if (len(roots) == 0 || s.forceAllDirs) && len(others) > 0 {
		roots = append(roots, s.findRootModules(target, others...)...)
	}

	return s.removeNestedDirs(roots)
}

func isRootModule(target fs.FS, dir string) bool {
	files, err := fs.ReadDir(target, dir)
	if err != nil {
		return false
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".tf") || strings.HasSuffix(file.Name(), ".tf.json") {
			return true
		}
	}
	return false
}
