package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/antchfx/htmlquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseActionTableURLs(t *testing.T) {

	doc, err := htmlquery.LoadDoc(filepath.Join("testdata", "reference_policies_actions-resources-contextkeys.html"))
	require.NoError(t, err)

	urls, err := parseServiceURLs(doc)
	require.NoError(t, err)

	expected := []string{
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsaccountmanagement.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsactivate.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_alexaforbusiness.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonmediaimport.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsamplify.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsamplifyadmin.html",
		"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsamplifyuibuilder.html",
	}
	assert.Equal(t, expected, urls)
}

func TestParseServicePrefix(t *testing.T) {

	doc, err := htmlquery.LoadDoc(filepath.Join("testdata", "list_amazoncloudwatch.html"))
	require.NoError(t, err)

	servicePrefix, err := parseServicePrefix(doc)
	require.NoError(t, err)

	assert.Equal(t, "cloudwatch", servicePrefix)
}

func TestParseActionsFromTable(t *testing.T) {

	doc, err := htmlquery.LoadDoc(filepath.Join("testdata", "list_amazoncloudwatch.html"))
	require.NoError(t, err)

	actions, err := parseServiceActions(doc)
	require.NoError(t, err)

	expected := []string{
		"DeleteAnomalyDetector",
		"DescribeAlarmsForMetric",
		"DescribeAnomalyDetectors",
		"DescribeInsightRules",
		"GetMetricData",
		"GetMetricStatistics",
		"GetMetricWidgetImage",
		"Link",
		"ListDashboards",
		"ListManagedInsightRules",
		"ListMetricStreams",
		"ListMetrics",
		"PutAnomalyDetector",
		"PutManagedInsightRules",
		"PutMetricData",
	}

	assert.Equal(t, expected, actions)
}

func TestGenerateFile(t *testing.T) {
	tmpDir := t.TempDir()

	actions := []string{
		"account:DisableRegion",
		"account:EnableRegion",
		"account:ListRegions",
	}
	path := filepath.Join(tmpDir, "test.go")
	require.NoError(t, generateFile(path, actions))

	expected := `// Code generated by cmd/allowed_actions DO NOT EDIT.

package iam

var allowedActionsForResourceWildcardsMap = map[string]struct{}{
	"account:DisableRegion": {},
	"account:EnableRegion": {},
	"account:ListRegions": {},
}`

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.Equal(t, expected, string(b))
}
