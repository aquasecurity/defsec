package formatters

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/defsec/pkg/scan"
)

// see https://github.com/windyroad/JUnit-Schema/blob/master/JUnit.xsd
// tested with CircleCI

// jUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type jUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Failures  string          `xml:"failures,attr"`
	Tests     string          `xml:"tests,attr"`
	TestCases []jUnitTestCase `xml:"testcase"`
}

// jUnitTestCase is a single test case with its result.
type jUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *jUnitFailure `xml:"failure,omitempty"`
}

// jUnitFailure contains data related to a failed test.
type jUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

func outputJUnit(b ConfigurableFormatter, results scan.Results) error {

	output := jUnitTestSuite{
		Name:     filepath.Base(os.Args[0]),
		Failures: fmt.Sprintf("%d", len(results)-countPassedResults(results)),
		Tests:    fmt.Sprintf("%d", len(results)),
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
		path := b.Path(res)
		output.TestCases = append(output.TestCases,
			jUnitTestCase{
				Classname: path,
				Name:      fmt.Sprintf("[%s][%s] - %s", res.Rule().LongID(), res.Severity(), res.Description()),
				Time:      "0",
				Failure:   buildFailure(b, res),
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

// highlight the lines of code which caused a problem, if available
func highlightCodeJunit(res scan.Result) string {
	code, err := res.GetCode()
	if err != nil {
		return ""
	}
	var output string
	for _, line := range code.Lines {
		if line.IsCause {
			output += fmt.Sprintf("%s\n", line.Content)
		}
	}
	return output
}

func buildFailure(b ConfigurableFormatter, res scan.Result) *jUnitFailure {
	if res.Status() == scan.StatusPassed {
		return nil
	}

	var link string
	links := b.GetLinks(res)
	if len(links) > 0 {
		link = links[0]
	}

	return &jUnitFailure{
		Message: res.Description(),
		Contents: fmt.Sprintf("%s\n%s\n%s",
			res.Range().String(),
			highlightCodeJunit(res),
			link,
		),
	}
}

func countPassedResults(results []scan.Result) int {
	passed := 0

	for _, res := range results {
		if res.Status() == scan.StatusPassed {
			passed++
		}
	}

	return passed
}
