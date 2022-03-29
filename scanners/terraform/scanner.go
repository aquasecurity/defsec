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
	"time"

	"github.com/aquasecurity/defsec/extrafs"

	"github.com/aquasecurity/defsec/rego"

	"github.com/aquasecurity/defsec/parsers/terraform/parser"
	"github.com/aquasecurity/defsec/parsers/terraform/parser/resolvers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/scanners/terraform/executor"
)

type Scanner struct {
	parserOpt        []parser.Option
	executorOpt      []executor.Option
	dirs             map[string]struct{}
	forceAllDirs     bool
	debugWriter      io.Writer
	policyDirs       []string
	policyNamespaces []string
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
	prefix := "[debug:scan] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) Scan(ctx context.Context, target fs.FS, dir string) (rules.Results, Metrics, error) {

	var metrics Metrics

	// find directories which directly contain tf files (and have no parent containing tf files)
	rootDirs := s.findRootModules(target, dir)
	sort.Strings(rootDirs)

	regoScanner := rego.NewScanner(
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
	)
	if err := regoScanner.LoadPolicies(true, s.policyDirs...); err != nil {
		return nil, Metrics{}, err
	}
	s.executorOpt = append(s.executorOpt, executor.OptionWithRegoScanner(regoScanner))

	var allResults rules.Results

	// parse all root module directories
	for _, dir := range rootDirs {

		s.debug("Scanning root module '%s'...", dir)

		p := parser.New(s.parserOpt...)
		e := executor.New(s.executorOpt...)

		if err := p.ParseFS(ctx, target, dir); err != nil {
			return nil, metrics, err
		}

		modules, _, err := p.EvaluateAll(context.TODO(), target)
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
