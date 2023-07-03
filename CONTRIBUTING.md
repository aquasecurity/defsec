
# Contributing

Welcome, and thank you for considering contributing to defsec!

The following guide gives an overview of the project and some directions on how to make common types of contribution. If something is missing or you get stuck, please [jump on Slack](https://slack.aquasec.com/) or [start a discussion](https://github.com/aquasecurity/defsec/discussions/new) and we'll do our best to help.

## Project Overview

_defsec_ is a library for defining security rules and policies in code, and the tools to apply those rules/cloud/policies to a variety of sources. The general architecture and project layout are defined in [ARCHITECTURE.md](ARCHITECTURE.md) - this is a great place to start exploring.

_defsec_ is also the misconfiguration/IaC/Cloud scanning engine for Trivy. Trivy uses defsec internally as a library to perform various scans. 

## Guides

The following are guides for contributing to the project in specific ways. If you're not sure where to start, these are a good place to look. If you need some tips on getting started with contributing to open source in general, check out this useful [GitHub contribution guide](https://docs.github.com/en/get-started/quickstart/contributing-to-projects).

### Writing Rules

Writing a new rule can be relatively simple, but there are a few things to keep in mind. The following guide will help you get started.

First of all, you should check if the provider your rule targets is supported by _defsec_. If it's not, you'll need to add support for it. See [Adding Support for a New Cloud Provider](#adding-support-for-a-new-cloud-provider) for more information. You can check if support exists by looking for a directory with the provider name in `pkg/providers`.  If you find your provider, navigate into the directory and check for a directory with the name of the service you're targeting. If you can't find that, you'll need to add support for it. See [Adding Support for a New Service](#adding-support-for-a-new-service) for more information.

Next up, you'll need to check if the properties you want to target are supported, and if not, add support for them. The guide on [Adding Support for a New Service](#adding-support-for-a-new-service) covers adding new properties.

At last, it's time to write your rule code! Rules are defined using _OPA Rego_. You can find a number of examples in the `rules/cloud/policies` directory. The [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) is a great place to start learning Rego. You can also check out the [Rego Playground](https://play.openpolicyagent.org/) to experiment with Rego, and [join the OPA Slack](https://slack.openpolicyagent.org/).

Create a new file in `rules/cloud/policies` with the name of your rule. You should nest it in the existing directory structure as applicable. The package name should be in the format `builtin.PROVIDER.SERVICE.ID`, e.g. `builtin.aws.rds.aws0176`.

Running `make id` will provide you with the next available _ID_ for your rule. You can use this ID in your rule code to identify it. 

A simple rule looks like the following example:

```rego
# METADATA
# title: "RDS IAM Database Authentication Disabled"
# description: "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   avd_id: AVD-AWS-0176
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-iam-auth
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.rds.aws0176

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

In fact, this is the code for an actual rule. You can find it in `rules/cloud/policies/aws/rds/enable_iam_auth.rego`. 

The metadata is the top section that starts with `# METADATA`, and is fairly verbose. You can copy and paste from another rule as a starting point. This format is effectively _yaml_ within a Rego comment, and is [defined as part of Rego itself](https://www.openpolicyagent.org/docs/latest/annotations/).

Let's break the metadata down. 

- `title` is fairly self explanatory - it is a title for the rule. The title should clearly and succinctly state the problem which is being detected.
- `description` is also fairly self explanatory - it is a description of the problem which is being detected. The description should be a little more verbose than the title, and should describe what the rule is trying to achieve. Imagine it completing a sentence starting with `You should...`.
- `scope` is used to define the scope of the policy. In this case, we are defining a policy that applies to the entire package. _defsec_ only supports using package scope for metadata at the moment, so this should always be the same.
- `schemas` tells Rego that it should use the `schema.input` to validate the use of the input data in the policy. Generally you can use this as-is in order to detect errors in your policy, such as referencing a policy which doesn't exist in the defsec schema.
- `custom` is used to define custom fields that can be used by defsec to provide additional context to the policy and any related detections. This can contain the following:
  - `avd_id` is the ID of the rule in the [AWS Vulnerability Database](https://avd.aquasec.com/). This is used to link the rule to the AVD entry. You can generate an ID to use for this field using `make id`.
  - `provider` is the name of the provider the rule targets. This should be the same as the provider name in the `pkg/providers` directory, e.g. `aws`.
  - `service` is the name of the service the rule targets. This should be the same as the service name in the `pkg/providers` directory, e.g. `rds`.
  - `severity` is the severity of the rule. This should be one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
  - `short_code` is a short code for the rule. This should be a short, descriptive name for the rule, separating words with hyphens. You should omit provider/service from this.
  - `recommended_action` is a recommended remediation action for the rule. This should be a short, descriptive sentence describing what the user should do to resolve the issue.
  - `input` tells _defsec_ what inputs this rule should be applied to. Cloud provider rules should always use the `selector` input, and should always use the `type` selector with `cloud`. Rules targeting Kubernetes yaml can use `kubenetes`, RBAC can use `rbac`, and so on. 

Now you'll need to write the rule logic. This is the code that will be executed to detect the issue. You should define a rule named `deny` and place your code inside this. 

```rego
deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

The rule should return a result, which can be created using `result.new` (this function does not need to be imported, it is defined internally and provided at runtime). The first argument is the message to display, and the second argument is the resource that the issue was detected on.

In the example above, you'll notice properties are being accessed from the `input.aws` object. The full set of schemas containing all of these properties is [available here](https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas). You can match the schema name to the type of input you want to scan.

You should also write a test for your rule(s). There are many examples of these in the `rules/cloud/policies` directory.

Finally, you'll want to run `make docs` to generate the documentation for your new policy.

You can see a full example PR for a new rule being added here: [https://github.com/aquasecurity/defsec/pull/1000](https://github.com/aquasecurity/defsec/pull/1000).


### Adding Support for a New Cloud Provider

If you want to add support for a new cloud provider, you'll need to add a new subdirectory to the `pkg/providers` directory, named after your provider. Inside this, create a Go file with the same name, and create a struct to hold information about all of the services supported by your provider.

For example, adding support for a new provider called `foo` would look like this:

`pkg/providers/foo/foo.go`:

```go
package foo

type Foo struct {
	// Add services here later...
}
```

Next you should add a reference to your provider struct in `pkg/state/state.go`:

```go
type State struct {
	// ...
    Foo foo.Foo
	// ...
}
```

Next up you'll need to add one or more _adapters_ to `internal/adapters`. An adapter takes an input and populates your provider struct. For example, if you want to scan a Terraform plan, you'll need to add an adapter that takes the Terraform plan and populates your provider struct. The AWS provider support in _defsec_ uses multiple adapters - it can adapt CloudFormation, Terraform, and live AWS accounts. Each of these has an adapter in this directory.

To support Terraform as an input, your adapter should look something like this:

```go
func Adapt(modules terraform.Modules) (foo.Foo, error) {
    return foo.Foo{
		// ...
    }, nil
}
```

...and should be called in `internal/adapters/terraform/adapt.go`. 

It's a good idea to browse the existing adapters to see how they work, as there is a lot of common code that can be reused.

### Adding Support for a New Service

Adding a new service involves two steps. The service will need a data structure to store information about the required resources, and then one or more adapters to convert input(s) into the aforementioned data structure.

To add a new service named `bar` to a provider named `foo`, you'll need to add a new file at `pkg/providers/foo/bar/bar.go`:

```go
type Bar struct {
    // ...
}
```

Let's say the `Bar` service manages resources called `Baz`. You'll need to add a new struct to the `Bar` struct to hold information about this resource:

```go
type Bar struct {
    // ...
    Baz []Baz
    // ...
}

type Baz struct {
    types.Metadata
	Name types.StringValue
	Encrypted types.BoolValue
}
```

A _Baz_ can have a name, and can optionally be encrypted. Instead of using raw `string` and `bool` types respectively, we use the _defsec_ types `types.StringValue` and `types.BoolValue`. These types wrap the raw values and provide additional metadata about the value, such as whether it was set by the user or not, and the file and line number where the resource was defined. The `types.Metadata` struct is embedded in all of the _defsec_ types, and provides a common set of metadata for all resources. This includes the file and line number where the resource was defined, and the name of the resource.

Next you'll need to add a reference to your new service struct in the provider struct at `pkg/providers/foo/foo.go`:

```go
type Foo struct {
    // ...
    Bar bar.Bar
    // ...
}
```

Now you'll need to update all of the adapters which populate the `Foo` provider struct. For example, if you want to support Terraform, you'll need to update `internal/adapters/terraform/foo/bar/adapt.go`.

Finally, make sure you run `make schema` to generate the schema for your new service.
