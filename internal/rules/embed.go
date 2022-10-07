package rules

import (
	"embed"
)

//go:embed policies/*/policies
var EmbeddedPolicyFileSystem embed.FS

//go:embed policies/*/lib
var EmbeddedLibraryFileSystem embed.FS
