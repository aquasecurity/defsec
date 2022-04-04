package formatters

import (
	"encoding/csv"
	"fmt"
	"strconv"

	"github.com/aquasecurity/defsec/pkg/scan"
)

func outputCSV(b ConfigurableFormatter, results scan.Results) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

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
		var link string
		links := b.GetLinks(res)
		if len(links) > 0 {
			link = links[0]
		}

		rng := res.Range()

		records = append(records, []string{
			rng.GetFilename(),
			strconv.Itoa(rng.GetStartLine()),
			strconv.Itoa(rng.GetEndLine()),
			res.Rule().LongID(),
			string(res.Severity()),
			res.Description(),
			link,
			strconv.FormatBool(res.Status() == scan.StatusPassed),
		})
	}

	csvWriter := csv.NewWriter(b.Writer())

	for _, record := range records {
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("error writing record to csv: `%w`", err)
		}
	}

	csvWriter.Flush()

	return csvWriter.Error()
}
