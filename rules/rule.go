package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/severity"
)

type EngineMetadata struct {
	GoodExamples        []string `json:"good_examples,omitempty"`
	BadExamples         []string `json:"bad_examples,omitempty"`
	RemediationMarkdown string   `json:"remediation_markdown,omitempty"`
	Links               []string `json:"links,omitempty"`
}

type Rule struct {
	AVDID          string            `json:"avd_id"`
	ShortCode      string            `json:"short_code"`
	Summary        string            `json:"summary"`
	Explanation    string            `json:"explanation"`
	Impact         string            `json:"impact"`
	Resolution     string            `json:"resolution"`
	Provider       provider.Provider `json:"provider"`
	Service        string            `json:"service"`
	Links          []string          `json:"links"`
	Severity       severity.Severity `json:"severity"`
	Terraform      *EngineMetadata   `json:"terraform,omitempty"`
	CloudFormation *EngineMetadata   `json:"cloud_formation,omitempty"`
}

func (r Rule) LongID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", r.Provider, r.Service, r.ShortCode))
}

func (r Rule) ServiceDisplayName() string {
	return nicify(r.Service)
}

func (r Rule) ShortCodeDisplayName() string {
	return nicify(r.ShortCode)
}

var acronyms = []string{
	"aws",
	"ec2",
	"ecr",
	"eks",
	"efs",
	"kms",
	"https",
	"ssh",
	"http",
	"mq",
	"sns",
	"sqs",
	"iam",
	"alb",
	"lb",
	"elb",
	"tls",
}

var specials = map[string]string{
	"dynamodb":   "DynamoDB",
	"documentdb": "DocumentDB",
	"mysql":      "MySQL",
	"postgresql": "PostgreSQL",
}

func nicify(input string) string {
	input = strings.ToLower(input)
	for _, acronym := range acronyms {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", acronym)).ReplaceAllString(input, strings.ToUpper(acronym))
	}
	for replace, with := range specials {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", replace)).ReplaceAllString(input, with)
	}
	return strings.Title(strings.ReplaceAll(input, "-", " "))
}
