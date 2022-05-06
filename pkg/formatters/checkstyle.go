package formatters

import (
	"encoding/xml"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"
)

type checkstyleResult struct {
	Source   string `xml:"source,attr"`
	Line     int    `xml:"line,attr"`
	Column   int    `xml:"column,attr"`
	Severity string `xml:"severity,attr"`
	Message  string `xml:"message,attr"`
	Link     string `xml:"link,attr"`
}

type checkstyleFile struct {
	Name   string             `xml:"name,attr"`
	Errors []checkstyleResult `xml:"error"`
}

type checkstyleOutput struct {
	XMLName xml.Name         `xml:"checkstyle"`
	Version string           `xml:"version,attr"`
	Files   []checkstyleFile `xml:"file"`
}

func outputCheckStyle(b ConfigurableFormatter, results scan.Results) error {

	output := checkstyleOutput{
		Version: "5.0",
	}

	files := make(map[string][]checkstyleResult)

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

		path := b.Path(res)

		files[path] = append(
			files[path],
			checkstyleResult{
				Source:   res.Rule().LongID(),
				Line:     rng.GetStartLine(),
				Severity: convertSeverity(res.Severity()),
				Message:  res.Description(),
				Link:     link,
			},
		)
	}

	for name, fileResults := range files {
		output.Files = append(
			output.Files,
			checkstyleFile{
				Name:   name,
				Errors: fileResults,
			},
		)
	}

	if _, err := b.Writer().Write([]byte(xml.Header)); err != nil {
		return err
	}

	xmlEncoder := xml.NewEncoder(b.Writer())
	xmlEncoder.Indent("", "\t")

	return xmlEncoder.Encode(output)
}

func convertSeverity(s severity.Severity) string {
	switch s {
	case severity.Low:
		return "info"
	case severity.Medium:
		return "warning"
	case severity.High:
		return "error"
	case severity.Critical:
		return "error"
	}
	return "error"
}
