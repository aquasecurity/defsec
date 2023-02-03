package rules

import (
	"embed"
)

//go:embed rules/*/policies
var EmbeddedPolicyFileSystem embed.FS

//go:embed rules/*/lib
var EmbeddedLibraryFileSystem embed.FS
