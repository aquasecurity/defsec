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

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	chartName    string
	helmClient   *action.Install
	rootPath     string
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
	p.debug = debug.New(writer, "parse:helm")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(chartName string, options ...options.ParserOption) *Parser {

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true  // don't do anything
	client.Replace = true // skip name check
	client.ReleaseName = chartName
	client.ClientOnly = true // don't try to talk to a cluster

	p := &Parser{
		chartName:  chartName,
		helmClient: client,
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

		if isArchive(path) {
			tarFS, err := p.addTarToFS(path)
			if err != nil {
				return err
			}
			if err := p.ParseFS(ctx, tarFS, "."); err != nil {
				return err
			}
			return nil
		}

		return p.addPaths(ctx, path)
	}); err != nil {
		return err
	}

	return nil
}

func (p *Parser) addPaths(ctx context.Context, paths ...string) error {
	for _, path := range paths {
		if _, err := fs.Stat(p.workingFS, path); err != nil {
			return err
		}

		if strings.HasSuffix(path, "Chart.yaml") && p.rootPath == "" {
			p.rootPath = filepath.Dir(path)
		}
		p.filepaths = append(p.filepaths, path)
	}
	return nil
}

func (p *Parser) RenderedChartFiles() ([]ChartFile, error) {

	tempDir, err := ioutil.TempDir(os.TempDir(), p.chartName)
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
	return strings.TrimPrefix(lines[0], "# Source: ")
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

func (p *Parser) Required(path string) bool {
	if p.skipRequired {
		return true
	}
	return detection.IsType(path, nil, detection.FileTypeYAML)
}
