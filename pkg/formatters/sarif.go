package formatters

import (
	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

func outputSARIF(b ConfigurableFormatter, results scan.Results) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("tfsec", "https://tfsec.dev")
	report.AddRun(run)

	for _, res := range results {

		switch res.Status() {
		case scan.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case scan.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}

		rule := run.AddRule(res.Rule().LongID()).
			WithDescription(res.Rule().Summary)

		links := b.GetLinks(res)
		if len(links) > 0 {
			rule.WithHelpURI(links[0])
		}

		metadata := res.Metadata().Root()

		rng := metadata.Range()
		message := sarif.NewTextMessage(res.Description())
		region := sarif.NewSimpleRegion(rng.GetStartLine(), rng.GetEndLine())
		var level string
		switch res.Severity() {
		case severity.None:
			level = "none"
		case severity.Low:
			level = "note"
		case severity.Medium:
			level = "warning"
		case severity.High, severity.Critical:
			level = "error"
		}

		path := b.Path(res, metadata)

		location := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(path)).
			WithRegion(region)

		ruleResult := run.CreateResultForRule(rule.ID)

		ruleResult.WithMessage(message).
			WithLevel(level).
			AddLocation(sarif.NewLocation().WithPhysicalLocation(location))
	}

	return report.PrettyWrite(b.Writer())
}
