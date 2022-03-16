package formatters

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/rules"
)

func outputJSON(b ConfigurableFormatter, results rules.Results) error {
	jsonWriter := json.NewEncoder(b.Writer())
	jsonWriter.SetIndent("", "\t")
	var flatResults []rules.FlatResult
	for _, result := range results.GetFailed() {
		switch result.Status() {
		case rules.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case rules.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}
		flat := result.Flatten()
		flat.Links = b.GetLinks(result)
		flatResults = append(flatResults, flat)
	}
	return jsonWriter.Encode(struct {
		Results []rules.FlatResult `json:"results"`
	}{flatResults})
}
