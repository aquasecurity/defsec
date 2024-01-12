package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"
)

const (
	serviceAuthURL             = "https://docs.aws.amazon.com/service-authorization/latest/reference/"
	serviceActionReferencesURL = "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"
)

const targetFile = "./pkg/providers/aws/iam/actions.go"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

const defaultParallel = 10

func run() error {
	log.Println("Start parsing actions")
	startTime := time.Now()
	defer func() {
		log.Printf("Parsing is completed. Duration %fs", time.Since(startTime).Seconds())
	}()

	limit := flag.Int("limit", defaultParallel, fmt.Sprintf("number of goroutines for scraping pages (default %d)", defaultParallel))
	flag.Parse()

	doc, err := htmlquery.LoadURL(serviceActionReferencesURL)
	if err != nil {
		return fmt.Errorf("failed to retrieve action references: %w", err)
	}
	urls, err := parseServiceURLs(doc)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(context.TODO())
	g.SetLimit(*limit)

	// actions may be the same for services of different versions,
	// e.g. Elastic Load Balancing and Elastic Load Balancing V2
	actionsSet := make(map[string]struct{})

	var mu sync.Mutex

	for _, url := range urls {
		url := url
		if ctx.Err() != nil {
			break
		}
		g.Go(func() error {
			serviceActions, err := parseActions(url)
			if err != nil {
				return fmt.Errorf("failed to parse actions from %q: %w", url, err)
			}

			mu.Lock()
			for _, act := range serviceActions {
				actionsSet[act] = struct{}{}
			}
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	actions := make([]string, 0, len(actionsSet))

	for act := range actionsSet {
		actions = append(actions, act)
	}

	sort.Strings(actions)

	path := filepath.FromSlash(targetFile)
	if err := generateFile(path, actions); err != nil {
		return fmt.Errorf("failed to generate file: %w", err)
	}
	return nil
}

func parseServiceURLs(doc *html.Node) ([]string, error) {
	nodes, err := htmlquery.QueryAll(doc, `//div[@class="highlights"]/ul/li/a/@href`)
	if err != nil {
		return nil, fmt.Errorf("failed to search nodes: %w", err)
	}

	res := make([]string, 0, len(nodes))

	for _, node := range nodes {
		// <a href="./list_awsaccountmanagement.html">AWS Account Management</a>
		if node.FirstChild != nil {
			res = append(res, serviceAuthURL+node.FirstChild.Data[2:])
		}
	}

	return res, nil
}

func parseActions(url string) ([]string, error) {

	doc, err := htmlquery.LoadURL(url)
	if err != nil {
		return nil, err
	}

	servicePrefix, err := parseServicePrefix(doc)
	if err != nil {
		return nil, err
	}

	actions, err := parseServiceActions(doc)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0, len(actions))

	for _, act := range actions {
		res = append(res, servicePrefix+":"+act)
	}

	log.Printf("Parsing of %q actions is completed", servicePrefix)

	return res, nil
}

func parseServiceActions(doc *html.Node) ([]string, error) {
	table, err := htmlquery.Query(doc, `//div[@class="table-container"]/div/table/tbody`)
	if table == nil {
		return nil, errors.New("actions table not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}

	var actions []string

	var f func(*html.Node)
	f = func(n *html.Node) {
		for _, tr := range findSubtags(n, "tr") {
			var action string
			for k, td := range findSubtags(tr, "td") {
				// first column - action
				if k == 0 {
					if a := findSubtag(td, "a"); a != nil && a.FirstChild != nil {
						action = a.FirstChild.Data
					}

					// fourth column - resource type
					// If the column is empty, then the action does not support resource-level permissions
					// and you must specify all resources ("*") in your policy
				} else if action != "" && k == 3 && td.FirstChild == nil {
					actions = append(actions, action)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(table)

	return actions, err
}

func findSubtag(n *html.Node, tagName string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tagName {
			return c
		}
	}

	return nil
}

func findSubtags(n *html.Node, tagName string) []*html.Node {
	result := make([]*html.Node, 0)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tagName {
			result = append(result, c)
		}
	}
	return result
}

func parseServicePrefix(doc *html.Node) (string, error) {
	nodes, err := htmlquery.QueryAll(doc, `//div[@id="main-col-body"]/p/descendant-or-self::*/text()`)
	if err != nil {
		return "", fmt.Errorf("failed to query paragraph: %w", err)
	}

	var sb strings.Builder
	for _, node := range nodes {
		sb.WriteString(node.Data)
	}

	p := sb.String()
	sb.Reset()

	idx := strings.Index(p, "service prefix: ")
	if idx == -1 {
		return "", fmt.Errorf("failed extract service prefix from text: %s", p)
	}
	idx += len("service prefix: ")

	if len(p)-1 <= idx {
		return "", fmt.Errorf("failed to parse service prefix from text: %s", p)
	}

	var parsed bool
	for _, r := range p[idx:] {
		if r == ')' {
			parsed = true
			break
		}
		sb.WriteRune(r)
	}

	if !parsed {
		return "", fmt.Errorf("failed to parse service prefix from text: %s", p)
	}

	return sb.String(), nil
}

func generateFile(path string, actions []string) error {

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	_, _ = w.WriteString(
		`// Code generated by cmd/allowed_actions DO NOT EDIT.

package iam

var allowedActionsForResourceWildcardsMap = map[string]struct{}{
`,
	)

	for _, action := range actions {
		_, _ = w.WriteString("\t\"" + action + "\": {},\n")
	}
	_, _ = w.WriteString("}")

	return w.Flush()
}
