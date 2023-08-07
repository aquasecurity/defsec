package azure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sync"

	adapter "github.com/aquasecurity/defsec/internal/adapters/cloud"
	cloudoptions "github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/errs"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/azure"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/progress"
	_ "github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var _ ConfigurableAZUREScanner = (*Scanner)(nil)

type Scanner struct {
	sync.Mutex
	regoScanner           *rego.Scanner
	debug                 debug.Logger
	options               []options.ScannerOption
	progressTracker       progress.Tracker
	location              string
	endpoint              string
	services              []string
	frameworks            []framework.Framework
	spec                  string
	concurrencyStrategy   concurrency.Strategy
	policyDirs            []string
	policyReaders         []io.Reader
	policyFS              fs.FS
	dataFs                fs.FS
	loadEmbeddedPolicies  bool
	loadEmbeddedLibraries bool
	regoOnly              bool
}

func (s *Scanner) SetRegoOnly(value bool) {
	s.regoOnly = value
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) Name() string {
	return "AZURE API"
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "azure-api", "scanner")
}

func (s *Scanner) SetProgressTracker(t progress.Tracker) {
	s.progressTracker = t
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetPolicyFilesystem(fs fs.FS) {
	s.policyFS = fs
}

func (s *Scanner) SetDataFilesystem(fs fs.FS) {
	s.dataFs = fs
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) SetTraceWriter(writer io.Writer)   {}
func (s *Scanner) SetPerResultTracingEnabled(b bool) {}
func (s *Scanner) SetDataDirs(s2 ...string)          {}
func (s *Scanner) SetPolicyNamespaces(s2 ...string)  {}
func (s *Scanner) SetSkipRequiredCheck(b bool)       {}
func (s *Scanner) SetRegoErrorLimit(_ int)           {}

func AllSupportedServices() []string {
	return azure.AllServices()
}

func (s *Scanner) SetAZURELocation(location string) {
	s.location = location
}

func (s *Scanner) SetAZUREEndpoint(endpoint string) {
	s.endpoint = endpoint
}

func (s *Scanner) SetAZUREServices(services []string) {
	s.services = services
}

func (s *Scanner) SetConcurrencyStrategy(strategy concurrency.Strategy) {
	s.concurrencyStrategy = strategy
}

func New(opts ...options.ScannerOption) *Scanner {

	s := &Scanner{
		options:             opts,
		progressTracker:     progress.NoProgress,
		concurrencyStrategy: concurrency.DefaultStrategy,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) CreateState(ctx context.Context) (*state.State, error) {
	cloudState, err := adapter.AZUREAdapt(ctx, cloudoptions.AZUREOptions{
		ProgressTracker:     s.progressTracker,
		Location:            s.location,
		Endpoint:            s.endpoint,
		Services:            s.services,
		DebugWriter:         s.debug,
		ConcurrencyStrategy: s.concurrencyStrategy,
	})
	if err != nil {
		var adaptionError errs.AdapterError
		if errors.As(err, &adaptionError) {
			s.debug.Log("There were %d errors during adaption process: %s", len(adaptionError.Errors()), adaptionError)
		} else {
			return nil, err
		}
	}
	return cloudState, nil
}

func (s *Scanner) ScanWithStateRefresh(ctx context.Context) (results scan.Results, err error) {
	cloudState, err := s.CreateState(ctx)
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx, cloudState)
}

func (s *Scanner) Scan(ctx context.Context, cloudState *state.State) (results scan.Results, err error) {

	if cloudState == nil {
		return nil, fmt.Errorf("cloud state is nil")
	}

	// evaluate go rules
	if !s.regoOnly {
		for _, rule := range s.getRegisteredRules() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if rule.Rule().RegoPackage != "" {
				continue
			}
			ruleResults := rule.Evaluate(cloudState)
			if len(ruleResults) > 0 {
				s.debug.Log("Found %d results for %s", len(ruleResults), rule.Rule().AVDID)
				results = append(results, ruleResults...)
			}
		}
	}

	// evaluate rego rules
	regoScanner, err := s.initRegoScanner()
	if err != nil {
		return nil, err
	}
	regoResults, err := regoScanner.ScanInput(ctx, rego.Input{
		Contents: cloudState.ToRego(),
	})
	if err != nil {
		return nil, err
	}
	return append(results, regoResults...), nil
}

func (s *Scanner) getRegisteredRules() []rules.RegisteredRule {
	if len(s.frameworks) > 0 { // Only for maintaining backwards compat
		return rules.GetFrameworkRules(s.frameworks...)
	}
	return rules.GetSpecRules(s.spec)
}

func (s *Scanner) initRegoScanner() (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}

	srcFS := s.policyFS
	if srcFS == nil {
		if runtime.GOOS == "windows" {
			homeDrive := os.Getenv("HOMEDRIVE")
			if homeDrive == "" {
				homeDrive = "C:"
			}
			srcFS = os.DirFS(homeDrive + "\\")
		} else {
			srcFS = os.DirFS("/")
		}
	}

	regoScanner := rego.NewScanner(types.SourceCloud, s.options...)
	regoScanner.SetParentDebugLogger(s.debug)
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, srcFS, s.policyDirs, s.policyReaders); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}
