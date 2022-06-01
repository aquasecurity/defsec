package parser

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/zclconf/go-cty/cty"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_BasicParsing(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"test.tf": `

locals {
	proxy = var.cats_mother
}

variable "cats_mother" {
	default = "boots"
}

provider "cats" {

}

moved {

}

resource "cats_cat" "mittens" {
	name = "mittens"
	special = true
}

resource "cats_kitten" "the-great-destroyer" {
	name = "the great destroyer"
    parent = cats_cat.mittens.name
}

data "cats_cat" "the-cats-mother" {
	name = local.proxy
}

`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	blocks := modules[0].GetBlocks()

	// variable
	variables := blocks.OfType("variable")
	require.Len(t, variables, 1)
	assert.Equal(t, "variable", variables[0].Type())
	require.Len(t, variables[0].Labels(), 1)
	assert.Equal(t, "cats_mother", variables[0].TypeLabel())
	defaultVal := variables[0].GetAttribute("default")
	require.NotNil(t, defaultVal)
	assert.Equal(t, cty.String, defaultVal.Value().Type())
	assert.Equal(t, "boots", defaultVal.Value().AsString())

	// provider
	providerBlocks := blocks.OfType("provider")
	require.Len(t, providerBlocks, 1)
	assert.Equal(t, "provider", providerBlocks[0].Type())
	require.Len(t, providerBlocks[0].Labels(), 1)
	assert.Equal(t, "cats", providerBlocks[0].TypeLabel())

	// resources
	resourceBlocks := blocks.OfType("resource")

	sort.Slice(resourceBlocks, func(i, j int) bool {
		return resourceBlocks[i].TypeLabel() < resourceBlocks[j].TypeLabel()
	})

	require.Len(t, resourceBlocks, 2)
	require.Len(t, resourceBlocks[0].Labels(), 2)

	assert.Equal(t, "resource", resourceBlocks[0].Type())
	assert.Equal(t, "cats_cat", resourceBlocks[0].TypeLabel())
	assert.Equal(t, "mittens", resourceBlocks[0].NameLabel())

	assert.Equal(t, "mittens", resourceBlocks[0].GetAttribute("name").Value().AsString())
	assert.True(t, resourceBlocks[0].GetAttribute("special").Value().True())

	assert.Equal(t, "resource", resourceBlocks[1].Type())
	assert.Equal(t, "cats_kitten", resourceBlocks[1].TypeLabel())
	assert.Equal(t, "the great destroyer", resourceBlocks[1].GetAttribute("name").Value().AsString())
	assert.Equal(t, "mittens", resourceBlocks[1].GetAttribute("parent").Value().AsString())

	// data
	dataBlocks := blocks.OfType("data")
	require.Len(t, dataBlocks, 1)
	require.Len(t, dataBlocks[0].Labels(), 2)

	assert.Equal(t, "data", dataBlocks[0].Type())
	assert.Equal(t, "cats_cat", dataBlocks[0].TypeLabel())
	assert.Equal(t, "the-cats-mother", dataBlocks[0].NameLabel())

	assert.Equal(t, "boots", dataBlocks[0].GetAttribute("name").Value().AsString())
}

func Test_Modules(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "my-mod" {
	source = "../module"
	input = "ok"
}

output "result" {
	value = module.my-mod.mod_result
}
`,
		"module/module.tf": `
variable "input" {
	default = "?"
}

output "mod_result" {
	value = var.input
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true), options.ParserWithDebug(os.Stderr))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 2)
	rootModule := modules[0]
	childModule := modules[1]

	moduleBlocks := rootModule.GetBlocks().OfType("module")
	require.Len(t, moduleBlocks, 1)

	assert.Equal(t, "module", moduleBlocks[0].Type())
	assert.Equal(t, "module.my-mod", moduleBlocks[0].FullName())
	inputAttr := moduleBlocks[0].GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	rootOutputs := rootModule.GetBlocks().OfType("output")
	require.Len(t, rootOutputs, 1)
	assert.Equal(t, "output.result", rootOutputs[0].FullName())
	valAttr := rootOutputs[0].GetAttribute("value")
	require.NotNil(t, valAttr)
	require.Equal(t, cty.String, valAttr.Type())
	assert.Equal(t, "ok", valAttr.Value().AsString())

	childOutputs := childModule.GetBlocks().OfType("output")
	require.Len(t, childOutputs, 1)
	assert.Equal(t, "module.my-mod.output.mod_result", childOutputs[0].FullName())
	childValAttr := childOutputs[0].GetAttribute("value")
	require.NotNil(t, childValAttr)
	require.Equal(t, cty.String, childValAttr.Type())
	assert.Equal(t, "ok", childValAttr.Value().AsString())

}

func Test_NestedParentModule(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "my-mod" {
	source = "../."
	input = "ok"
}

output "result" {
	value = module.my-mod.mod_result
}
`,
		"root.tf": `
variable "input" {
	default = "?"
}

output "mod_result" {
	value = var.input
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 2)
	rootModule := modules[0]
	childModule := modules[1]

	moduleBlocks := rootModule.GetBlocks().OfType("module")
	require.Len(t, moduleBlocks, 1)

	assert.Equal(t, "module", moduleBlocks[0].Type())
	assert.Equal(t, "module.my-mod", moduleBlocks[0].FullName())
	inputAttr := moduleBlocks[0].GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	rootOutputs := rootModule.GetBlocks().OfType("output")
	require.Len(t, rootOutputs, 1)
	assert.Equal(t, "output.result", rootOutputs[0].FullName())
	valAttr := rootOutputs[0].GetAttribute("value")
	require.NotNil(t, valAttr)
	require.Equal(t, cty.String, valAttr.Type())
	assert.Equal(t, "ok", valAttr.Value().AsString())

	childOutputs := childModule.GetBlocks().OfType("output")
	require.Len(t, childOutputs, 1)
	assert.Equal(t, "module.my-mod.output.mod_result", childOutputs[0].FullName())
	childValAttr := childOutputs[0].GetAttribute("value")
	require.NotNil(t, childValAttr)
	require.Equal(t, cty.String, childValAttr.Type())
	assert.Equal(t, "ok", childValAttr.Value().AsString())
}

func Test_UndefinedModuleOutputReference(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
resource "something" "blah" {
	value = module.x.y
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, false, attr.IsResolvable())
}

func Test_UndefinedModuleOutputReferenceInSlice(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
resource "something" "blah" {
	value = ["first", module.x.y, "last"]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, false, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_TemplatedSliceValue(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "hello"
}

resource "something" "blah" {
	value = ["first", "${var.x}-${var.x}", "last"]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "hello-hello", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_SliceOfVars(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "1"
}

variable "y" {
	default = "2"
}

resource "something" "blah" {
	value = [var.x, var.y]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 2)

	assert.Equal(t, "1", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "2", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())
}

func Test_VarSlice(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = ["a", "b", "c"]
}

resource "something" "blah" {
	value = var.x
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_LocalSliceNested(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "a"
}

locals {
	y = [var.x, "b", "c"]
}

resource "something" "blah" {
	value = local.y
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_FunctionCall(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = ["a", "b"]
}

resource "something" "blah" {
	value = concat(var.x, ["c"])
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	if err := parser.ParseFS(context.TODO(), "code"); err != nil {
		t.Fatal(err)
	}
	modules, _, err := parser.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty(block)
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}
