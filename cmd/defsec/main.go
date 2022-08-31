package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "defsec",
	Short: "defsec is a tool to scan filesystems and cloud accounts for security vulnerabilities and misconfigurations",
}

var (
	flagDebug  = false
	flagFormat = "simple"
)

func main() {

	rootCmd.PersistentFlags().BoolVarP(&flagDebug, "debug", "d", flagDebug, "enable debug output")
	rootCmd.PersistentFlags().StringVarP(&flagFormat, "format", "f", flagFormat, "output format (simple, sarif, json, csv, checkstyle, junit)")

	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
