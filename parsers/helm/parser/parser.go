package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
)

type Parser struct {
	chartName   string
	helmClient  *action.Install
	rootPath    string
	filepaths   []string
	debugWriter io.Writer
}

type ChartFile struct {
	TemplateFilePath string
	ManifestContent  string
}

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

func New(chartName string, options ...Option) *Parser {

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

func (p *Parser) debug(format string, args ...interface{}) {
	if p.debugWriter == nil {
		return
	}
	prefix := "[debug:parse] "
	_, _ = p.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (p *Parser) AddPaths(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return err
		}

		if isArchive(path) {
			return p.addTarball(path)
		}

		if strings.HasSuffix(path, "Chart.yaml") && p.rootPath == "" {
			p.rootPath = filepath.Dir(path)
		}
		p.filepaths = append(p.filepaths, path)
	}
	return nil
}

func (p *Parser) RenderedChartFiles() ([]ChartFile, error) {

	tempFs, err := ioutil.TempDir(os.TempDir(), p.chartName)
	if err != nil {
		return nil, err
	}

	if err := p.writeBuildFiles(tempFs); err != nil {
		return nil, err
	}

	chart, err := loadChart(tempFs)
	if err != nil {
		return nil, err
	}

	release, err := p.getRelease(chart)
	if err != nil {
		return nil, err
	}

	var manifests bytes.Buffer
	fmt.Fprintln(&manifests, strings.TrimSpace(release.Manifest))

	splitManifests := releaseutil.SplitManifests(manifests.String())
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	return p.getRenderedManifests(manifestsKeys, splitManifests), nil
}

func (p *Parser) getRelease(chart *chart.Chart) (*release.Release, error) {

	release, err := p.helmClient.RunWithContext(context.Background(), chart, nil)
	if err != nil {
		return nil, err
	}

	if release == nil {
		return nil, fmt.Errorf("there is nothing in the release")
	}
	return release, nil
}

func loadChart(tempFs string) (*chart.Chart, error) {
	chart, err := loader.Load(tempFs)
	if err != nil {
		return nil, err
	}

	if req := chart.Metadata.Dependencies; req != nil {
		if err := action.CheckDependencies(chart, req); err != nil {
			return nil, err
		}
	}
	return chart, nil
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
		content, err := os.ReadFile(path)
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
