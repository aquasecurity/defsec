package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aquasecurity/defsec/types"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/defsec/rules"

	cfRules "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
)

var ruleMu sync.Mutex
var registeredRules []cfRules.Rule

func RegisterCheckRule(rules ...cfRules.Rule) {
	for i, rule := range rules {
		cfsecLink := fmt.Sprintf("https://cfsec.dev/docs/%s/%s/#%s", rule.Base.Rule().Service, rule.Base.Rule().ShortCode, rule.Base.Rule().Service)
		rules[i].Base.AddLink(cfsecLink)
	}

	ruleMu.Lock()
	defer ruleMu.Unlock()
	registeredRules = append(registeredRules, rules...)
}

func DeregisterRuleByID(id string) {
	ruleMu.Lock()
	defer ruleMu.Unlock()
	var filtered []cfRules.Rule
	for _, rule := range registeredRules {
		if rule.ID() == id {
			continue
		}
		filtered = append(filtered, rule)
	}
	registeredRules = filtered
}

// Scanner ...
type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Scan ...
func (scanner *Scanner) Scan(contexts parser.FileContexts) []rules.Result {
	var results []rules.Result
	for _, ctx := range contexts {
		if ctx == nil {
			continue
		}
		s := adapter.Adapt(*ctx)
		if s == nil {
			continue
		}
		for _, rule := range GetRegisteredRules() {
			debug.Log("Executing rule: %s", rule.LongID())
			evalResult := rule.Base.Evaluate(s)
			if len(evalResult) > 0 {
				debug.Log("Found %d results for %s", len(evalResult), rule.LongID())
				for _, scanResult := range evalResult {

					ref := scanResult.CodeBlockMetadata().Reference()
					if scanResult.IssueBlockMetadata() != nil {
						ref = scanResult.IssueBlockMetadata().Reference()
					}
					reference := ref.(*parser.CFReference)

					if !isIgnored(scanResult) {
						description := getDescription(scanResult, reference)
						scanResult.OverrideDescription(description)
						if reference.PropertyRange() != nil {
							meta := types.NewMetadata(
								reference.PropertyRange(),
								reference,
							)
							scanResult.OverrideIssueBlockMetadata(&meta)
							scanResult.OverrideAnnotation(reference.DisplayValue())
						}
						if scanResult.Status() == rules.StatusPassed && !scanner.includePassed {
							continue
						}
						results = append(results, scanResult)
					}
				}
			}
		}
	}
	return results
}

func getDescription(scanResult rules.Result, location *parser.CFReference) string {
	if scanResult.Status() != rules.StatusPassed {
		return scanResult.Description()
	}
	return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
}

// GetRegisteredRules provides all Checks which have been registered with this package

func GetRegisteredRules() []cfRules.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

// GetRuleByLongID ...
func GetRuleByLongID(long string) (*cfRules.Rule, error) {

	for _, r := range registeredRules {
		if r.LongID() == long {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with long ID '%s'", long)
}
