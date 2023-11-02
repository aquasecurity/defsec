
# Contributing

Welcome, and thank you for considering contributing to defsec!

The following guide gives an overview of the project and some directions on how to make common types of contribution. If something is missing, or you get stuck, please [start a discussion](https://github.com/aquasecurity/trivy/discussions/new) and we'll do our best to help.

## Project Overview

_defsec_ repo is a collection of shared libraries and packages that are imported by other useful packages such as `trivy-iac`, `trivy-aws` and also `Trivy` directly.

_trivy-iac_ is the collection of all Infrastructure-as-code libraries and packages that Trivy uses to perform IaC scanning. It also where you can find `schemas` to write custom polices.

_trivy-aws_ is the AWS scanning component of Trivy.

_trivy-policies_ is the repo that holds all misconfiguration checks for `Trivy`. It also hosts the policy bundles for misconfiguration scanning that `Trivy` uses.

You can read more about the project overview on the [architecture](./ARCHITECTURE.md) page.

## Guides

The following are guides for contributing to the project in specific ways. If you're not sure where to start, these are a good place to look. If you need some tips on getting started with contributing to open source in general, check out this useful [GitHub contribution guide](https://docs.github.com/en/get-started/quickstart/contributing-to-projects).

### Writing New Policies
You can find a guide to writing new policies [insert link here from trivy-policies repo]()

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
