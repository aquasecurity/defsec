package parser

import (
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/defsec/providers/dockerfile"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"golang.org/x/xerrors"
)

type Parser struct{}

// New creates a new Dockerfile parser
func New() *Parser {
	return &Parser{}
}

// ParseFile parses a Dockerfile from the given path
func (p *Parser) ParseFile(path string) (*dockerfile.Dockerfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return p.Parse(path, f)
}

// Parse parses Dockerfile content from the provided reader. The path is provided purely for metadata, it does not have to exist.
func (p *Parser) Parse(path string, r io.Reader) (*dockerfile.Dockerfile, error) {
	parsed, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("dockerfile parse error: %w", err)
	}

	var parsedFile dockerfile.Dockerfile
	parsedFile.Stages = make(map[string][]dockerfile.Command)

	var stageIndex int
	fromValue := "args"
	for _, child := range parsed.AST.Children {
		child.Value = strings.ToLower(child.Value)

		instr, err := instructions.ParseInstruction(child)
		if err != nil {
			return nil, xerrors.Errorf("process dockerfile instructions: %w", err)
		}

		if _, ok := instr.(*instructions.Stage); ok {
			if fromValue != "args" {
				stageIndex++
			}
			fromValue = strings.TrimSpace(strings.TrimPrefix(child.Original, "FROM "))
		}

		cmd := dockerfile.Command{
			Cmd:       child.Value,
			Original:  child.Original,
			Flags:     child.Flags,
			Stage:     stageIndex,
			Path:      path,
			StartLine: child.StartLine,
			EndLine:   child.EndLine,
		}

		if child.Next != nil && len(child.Next.Children) > 0 {
			cmd.SubCmd = child.Next.Children[0].Value
			child = child.Next.Children[0]
		}

		cmd.JSON = child.Attributes["json"]
		for n := child.Next; n != nil; n = n.Next {
			cmd.Value = append(cmd.Value, n.Value)
		}

		parsedFile.Stages[fromValue] = append(parsedFile.Stages[fromValue], cmd)

	}

	//j, err := json.Marshal()
	//if err != nil {
	//	return nil, xerrors.Errorf("json marshal error: %w", err)
	//}
	//
	//var res interface{}
	//if err = json.Unmarshal(j, &res); err != nil {
	//	return nil, xerrors.Errorf("json unmarshal error: %w", err)
	//}

	return &parsedFile, nil
}
