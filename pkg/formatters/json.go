package formatters

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/pkg/scan"
)

func outputJSON(b ConfigurableFormatter, results scan.Results) error {
	jsonWriter := json.NewEncoder(b.Writer())
	jsonWriter.SetIndent("", "\t")
	var flatResults []scan.FlatResult
	for _, result := range results.GetFailed() {
		switch result.Status() {
		case scan.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case scan.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}
		flat := result.Flatten()
		flat.Links = b.GetLinks(result)
		flatResults = append(flatResults, flat)
	}
	return jsonWriter.Encode(struct {
		Results []scan.FlatResult `json:"results"`
	}{flatResults})
}
