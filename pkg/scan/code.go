package scan

import (
	"fmt"
	"io/fs"
	"strings"
)

type Code struct {
	lines []Line
}

type Line struct {
	Number     int
	Content    string
	IsCause    bool
	Annotation string
}

func (c *Code) Lines() []Line {
	return c.lines
}

func (c *Code) IsCauseMultiline() bool {
	var count int
	for _, line := range c.lines {
		if line.IsCause {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

func (r *Result) GetCode() (*Code, error) {

	srcFS := r.Metadata().Range().GetFS()
	if srcFS == nil {
		return nil, fmt.Errorf("code unavailable: result was not mapped to a known filesystem")
	}

	innerRange := r.Range()
	outerRange := innerRange
	if !innerRange.IsMultiLine() {
		metadata := r.Metadata()
		if parent := metadata.Parent(); parent != nil {
			outerRange = parent.Range()
		}
	}

	content, err := fs.ReadFile(srcFS, r.fsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file from result filesystem (%#v): %w", srcFS, err)
	}

	hasAnnotation := r.Annotation() != ""

	code := Code{
		lines: nil,
	}

	rawLines := strings.Split(string(content), "\n")

	if outerRange.GetEndLine()-1 >= len(rawLines) || innerRange.GetStartLine() == 0 {
		return nil, fmt.Errorf("invalid line number")
	}

	for lineNo := outerRange.GetStartLine(); lineNo <= outerRange.GetEndLine(); lineNo++ {

		line := Line{
			Number:  lineNo,
			Content: strings.TrimSuffix(rawLines[lineNo-1], "\r"),
			IsCause: lineNo >= innerRange.GetStartLine() && lineNo <= innerRange.GetEndLine(),
		}

		if hasAnnotation && lineNo == innerRange.GetStartLine() {
			line.Annotation = r.Annotation()
		}

		code.lines = append(code.lines, line)
	}

	return &code, nil
}
