package parser

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

type sourceFile struct {
	file *hcl.File
	path string
}

type Parser interface {
	ParseFile(path string) error
	ParseDirectory(path string) error
	EvaluateAll() (terraform.Modules, error)
}

// Parser is a tool for parsing terraform templates at a given file system location
type parser struct {
	projectRoot    string
	files          []sourceFile
	excludePaths   []string
	tfvarsPaths    []string
	stopOnHCLError bool
	stopOnFirstTf  bool
	workspaceName  string
	skipDownloaded bool
	underlying     *hclparse.Parser
}

// New creates a new Parser
func New(options ...Option) Parser {
	p := &parser{
		stopOnFirstTf: true,
		workspaceName: "default",
		underlying:    hclparse.NewParser(),
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func (p *parser) ParseFile(fullPath string) error {

	if dir := filepath.Dir(fullPath); p.projectRoot == "" || len(dir) < len(p.projectRoot) {
		p.projectRoot = dir
	}

	var parseFunc func(filename string) (*hcl.File, hcl.Diagnostics)

	switch {
	case strings.HasSuffix(fullPath, ".tf"):
		parseFunc = p.underlying.ParseHCLFile
	case strings.HasSuffix(fullPath, ".tf.json"):
		parseFunc = p.underlying.ParseJSONFile
	default:
		return nil
	}

	file, diag := parseFunc(fullPath)
	if diag != nil && diag.HasErrors() {
		return diag
	}
	p.files = append(p.files, sourceFile{
		file: file,
		path: fullPath,
	})
	return nil
}

// ParseDirectory parses all terraform files within a given directory
func (p *parser) ParseDirectory(fullPath string) error {

	if p.projectRoot == "" {
		p.projectRoot = fullPath
	}

	////debug.Log("Finding Terraform subdirectories...")
	//diskTimer := metrics.Timer("timings", "disk i/o")
	//diskTimer.Start()
	subdirectories, err := p.getSubdirectories(fullPath)
	if err != nil {
		return err
	}
	//diskTimer.Stop()

	for _, dir := range subdirectories {
		fileInfos, err := ioutil.ReadDir(dir)
		if err != nil {
			return err
		}

		for _, info := range fileInfos {
			if info.IsDir() {
				continue
			}
			if err := p.ParseFile(filepath.Join(fullPath, info.Name())); err != nil {
				if p.stopOnHCLError {
					return err
				}
				continue
			}
		}
	}

	return nil
}

func (p *parser) EvaluateAll() (terraform.Modules, error) {

	if len(p.files) == 0 {
		return nil, nil
	}

	blocks, ignores, err := p.evaluateFiles(p.files)
	if err != nil {
		return nil, err
	}

	inputVars, err := loadTFVars(p.tfvarsPaths)
	if err != nil {
		return nil, err
	}

	var modulesMetadata *modulesMetadata
	if p.skipDownloaded {
		//debug.Log("Skipping module metadata loading, --exclude-downloaded-modules passed")
	} else {
		//debug.Log("Loading module metadata...")
		modulesMetadata, _ = loadModuleMetadata(p.projectRoot)
		// TODO: report error and continue?
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	evaluator := newEvaluator(
		p.projectRoot,
		p.projectRoot,
		workingDir,
		"root",
		blocks,
		inputVars,
		modulesMetadata,
		nil,
		p.workspaceName,
		ignores,
		p.stopOnHCLError,
	)
	return evaluator.EvaluateAll(), nil
}

func (p *parser) evaluateFiles(files []sourceFile) (terraform.Blocks, terraform.Ignores, error) {
	var blocks terraform.Blocks
	var ignores terraform.Ignores

	for _, file := range files {
		fileBlocks, fileIgnores, err := loadBlocksFromFile(file)
		if err != nil {
			if p.stopOnHCLError {
				return nil, nil, err
			}
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
			continue
		}
		if len(fileBlocks) > 0 {
			////debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, terraform.NewBlock(fileBlock, nil, nil, nil))
		}
		ignores = append(ignores, fileIgnores...)
	}

	sortBlocksByHierarchy(blocks)
	return blocks, ignores, nil
}

func (p *parser) getSubdirectories(path string) ([]string, error) {

	if p.skipDownloaded && filepath.Base(path) == ".terraform" {
		return nil, nil
	}

	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	entries = p.removeExcluded(path, entries)
	var results []string
	for _, entry := range entries {

		if !entry.IsDir() && (filepath.Ext(entry.Name()) == ".tf" || strings.HasSuffix(entry.Name(), ".tf.json")) {
			//debug.Log("Found qualifying subdirectory containing .tf files: %s", path)
			results = append(results, path)
			if p.stopOnFirstTf {
				return results, nil
			}
			break
		}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			dirs, err := p.getSubdirectories(filepath.Join(path, entry.Name()))
			if err != nil {
				return nil, err
			}
			if p.stopOnFirstTf && len(dirs) > 0 {
				return dirs[:1], nil
			}
			results = append(results, dirs...)
		}
	}
	return results, nil
}

func (p *parser) removeExcluded(path string, entries []fs.FileInfo) (valid []fs.FileInfo) {
	if len(p.excludePaths) == 0 {
		return entries
	}
	for _, entry := range entries {
		var remove bool
		fullPath := filepath.Join(path, entry.Name())
		for _, excludePath := range p.excludePaths {
			if fullPath == excludePath {
				remove = true
			}
		}
		if !remove {
			valid = append(valid, entry)
		}
	}
	return valid
}
