
The main goal of this change is to wrap the rego policies included in defsec with a Go API, so that scans can be done with minimal coupling.

This means Trivy can use defsec directly to scan all configuration/IaC files, instead of proxying the scanning through fanal.

I have done my best to consider the preservation of all Trivy functionality as part of this change. Trivy users should not notice this change has happened once we start using it.

The following changes are also included as part of this work:

 - [x] `GetRegisteredRules()` now also includes all rego policies wrapped in the `Rule{}` type. This means that SaaS can now programmatically retrieve information about all rego policies for use in the SaaS UI, simply by importing the defsec Go module and calling `GetRegisteredRules()`.
 - [ ] Added a dockerfile scanner.
 - [ ] Added a k8s scanner.
 - [ ] Added a `universal` scanner which will apply rules depending on the filetype of the file(s) being scanned. This means Trivy does not need to determine the type of every IaC file or initialise separate scanners, it can initialise this single scanner and call `scanner.AddFile(path)`.
 - [x] Rego policies are now embedded in the go binary.
 - [x] Scanner(s) can optionally be provided with a directory for rego policies, otherwise embedded policies will be used.
 - [x] The `Result` type now supports a third possible status: `Ignored`. This will be used when checks are ignored/excluded e.g. by tfsec ignore rules, rego exclusion policies etc.
 - [ ] Rego policies have been updated to consistently return metadata instead of simple strings.
 - [x] Line numbers are now available in Docker rego result metadata, meaning we can highlight the individual line that caused a check to fail.
 - [ ] Custom rego policies can now also be included by a user to apply policies to resources defined in Terraform/CloudFormation
 - [x] The groundwork has been laid for the writing of rego policies for Ansible, Helm etc.
 - [ ] Remove version from metadata
