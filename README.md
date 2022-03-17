[![GoReportCard](https://goreportcard.com/badge/github.com/aquasecurity/defsec)](https://goreportcard.com/report/github.com/aquasecurity/defsec)
[![Join Our Slack](https://img.shields.io/badge/Slack-Join-green)](https://slack.aquasec.com/)

# defsec

DefSec is a collection of Infrastructure-as-Code rules. 

These rules as defined in Go and Rego.

Defining DefSec rules in this central repository means they can be used from various projects, regardless of the IaC implementation. For example, DefSec is currently used by both [tfsec](https://github.com/aquasecurity/tfsec) (for Terraform) and [cfsec](https://github.com/aquasecurity/cfsec) (CloudFormation). The same logic is applied to cloud resources defined in both source formats.

There's a detailed walkthrough for creating a new check in the [tfsec contributing guide](https://github.com/aquasecurity/tfsec/tree/master/CONTRIBUTING.md).

Please feel free to raise issues/discussions for anything else, or [join us on Slack](https://slack.aquasec.com/)!.
