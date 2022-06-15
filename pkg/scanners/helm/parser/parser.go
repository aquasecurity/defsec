package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/pkg/debug"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"

	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	helmClient   *action.Install
	rootPath     string
	ChartSource  string
	filepaths    []string
	debug        debug.Logger
	skipRequired bool
	workingFS    fs.FS
}

type ChartFile struct {
	TemplateFilePath string
	ManifestContent  string
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "helm", "parser")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(path string, options ...options.ParserOption) *Parser {

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true     // don't do anything
	client.Replace = true    // skip name check
	client.ClientOnly = true // don't try to talk to a cluster

	p := &Parser{
		helmClient:  client,
		ChartSource: path,
	}

	for _, option := range options {
		option(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) error {
	p.workingFS = target

	if err := fs.WalkDir(p.workingFS, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		if !p.required(path, p.workingFS) {
			return nil
		}

		if detection.IsArchive(path) {
			tarFS, err := p.addTarToFS(path)
			if err != nil {
				return err
			}
			if err := p.ParseFS(ctx, tarFS, "."); err != nil {
				return err
			}
			return nil
		}

		return p.addPaths(path)
	}); err != nil {
		return err
	}

	return nil
}

func (p *Parser) addPaths(paths ...string) error {
	for _, path := range paths {
		if _, err := fs.Stat(p.workingFS, path); err != nil {
			return err
		}

		if strings.HasSuffix(path, "Chart.yaml") && p.rootPath == "" {
			if err := p.extractChartName(path); err != nil {
				return err
			}
			p.rootPath = filepath.Dir(path)
		}
		p.filepaths = append(p.filepaths, path)
	}
	return nil
}

func (p *Parser) extractChartName(chartPath string) error {

	chart, err := p.workingFS.Open(chartPath)
	if err != nil {
		return err
	}
	defer func() { _ = chart.Close() }()

	var chartContent map[string]interface{}
	if err := yaml.NewDecoder(chart).Decode(&chartContent); err != nil {
		return err
	}

	if name, ok := chartContent["name"]; !ok {
		return fmt.Errorf("could not extract the chart name from %s", chartPath)
	} else {
		p.helmClient.ReleaseName = name.(string)
	}
	return nil
}

func (p *Parser) RenderedChartFiles() ([]ChartFile, error) {

	tempDir, err := ioutil.TempDir(os.TempDir(), "defsec")
	if err != nil {
		return nil, err
	}

	if err := p.writeBuildFiles(tempDir); err != nil {
		return nil, err
	}

	workingChart, err := loadChart(tempDir)
	if err != nil {
		return nil, err
	}

	workingRelease, err := p.getRelease(workingChart)
	if err != nil {
		return nil, err
	}

	var manifests bytes.Buffer
	_, _ = fmt.Fprintln(&manifests, strings.TrimSpace(workingRelease.Manifest))

	splitManifests := releaseutil.SplitManifests(manifests.String())
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	return p.getRenderedManifests(manifestsKeys, splitManifests), nil
}

func (p *Parser) getRelease(chart *chart.Chart) (*release.Release, error) {

	r, err := p.helmClient.RunWithContext(context.Background(), chart, nil)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return nil, fmt.Errorf("there is nothing in the r")
	}
	return r, nil
}

func loadChart(tempFs string) (*chart.Chart, error) {
	loadedChart, err := loader.Load(tempFs)
	if err != nil {
		return nil, err
	}

	if req := loadedChart.Metadata.Dependencies; req != nil {
		if err := action.CheckDependencies(loadedChart, req); err != nil {
			return nil, err
		}
	}
	return loadedChart, nil
}

func (*Parser) getRenderedManifests(manifestsKeys []string, splitManifests map[string]string) []ChartFile {
	sort.Sort(releaseutil.BySplitManifestsOrder(manifestsKeys))
	var manifestsToRender []ChartFile
	for _, manifestKey := range manifestsKeys {
		manifest := splitManifests[manifestKey]
		submatch := manifestNameRegex.FindStringSubmatch(manifest)
		if len(submatch) == 0 {
			continue
		}
		manifestsToRender = append(manifestsToRender, ChartFile{
			TemplateFilePath: getManifestPath(manifest),
			ManifestContent:  manifest,
		})
	}
	return manifestsToRender
}

func getManifestPath(manifest string) string {
	lines := strings.Split(manifest, "\n")
	if len(lines) == 0 {
		return "unknown.yaml"
	}
	manifestFilePathParts := strings.SplitN(strings.TrimPrefix(lines[0], "# Source: "), "/", 2)
	if len(manifestFilePathParts) > 1 {
		return manifestFilePathParts[1]
	}
	return manifestFilePathParts[0]
}

func (p *Parser) writeBuildFiles(tempFs string) error {
	for _, path := range p.filepaths {
		content, err := fs.ReadFile(p.workingFS, path)
		if err != nil {
			return err
		}
		workingPath := strings.TrimPrefix(path, p.rootPath)
		workingPath = filepath.Join(tempFs, workingPath)
		if err := os.MkdirAll(filepath.Dir(workingPath), os.ModePerm); err != nil {
			return err
		}
		if err := os.WriteFile(workingPath, content, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) required(path string, workingFS fs.FS) bool {
	if p.skipRequired {
		return true
	}
	content, err := fs.ReadFile(workingFS, path)
	if err != nil {
		return false
	}

	return detection.IsType(path, bytes.NewReader(content), detection.FileTypeHelm)
}
