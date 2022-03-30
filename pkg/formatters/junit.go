package formatters

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

func outputJUnit(b ConfigurableFormatter, srcFS fs.FS, results scan.Results) error {

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
		rng := res.Range()
		output.TestCases = append(output.TestCases,
			jUnitTestCase{
				Classname: rng.GetFilename(),
				Name:      fmt.Sprintf("[%s][%s] - %s", res.Rule().LongID(), res.Severity(), res.Description()),
				Time:      "0",
				Failure:   buildFailure(b, srcFS, res),
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
func highlightCodeJunit(srcFS fs.FS, res scan.Result) string {

	if srcFS == nil {
		return ""
	}

	data, err := fs.ReadFile(srcFS, res.Range().GetFilename())
	if err != nil {
		return ""
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	rng := res.Range()

	start := rng.GetStartLine() - 3
	if start <= 0 {
		start = 1
	}
	end := rng.GetEndLine() + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	output := ""

	for lineNo := start; lineNo <= end; lineNo++ {
		output += fmt.Sprintf("  % 6d | ", lineNo)
		if lineNo >= rng.GetStartLine() && lineNo <= rng.GetEndLine() {
			if lineNo == rng.GetStartLine() && res.Annotation() != "" {
				output += fmt.Sprintf("%s    %s\n", lines[lineNo], res.Annotation())
			} else {
				output += fmt.Sprintf("%s\n", lines[lineNo])
			}
		} else {
			output += fmt.Sprintf("%s\n", lines[lineNo])
		}
	}

	return output
}

func buildFailure(b ConfigurableFormatter, srcFS fs.FS, res scan.Result) *jUnitFailure {
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
			highlightCodeJunit(srcFS, res),
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
