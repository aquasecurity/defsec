package main

import (
	"context"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/defsec/pkg/extrafs"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/scanners/universal"
)

func init() {
	fsCmd := &cobra.Command{
		Use:   "fs [directory]",
		Short: "Scan a filesystem for misconfigurations of all types",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return scanFS(args[0], cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	rootCmd.AddCommand(fsCmd)
}

func scanFS(dir string, stdout, stderr io.Writer) error {

	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	filesystem := extrafs.OSDir(abs)

	opts := []options.ScannerOption{
		options.ScannerWithEmbeddedPolicies(true),
	}

	if flagDebug {
		opts = append(opts, options.ScannerWithDebug(stderr))
	}

	scanner := universal.New(opts...)

	// Execute the filesystem based scanners
	results, err := scanner.ScanFS(context.TODO(), filesystem, ".")
	if err != nil {
		return err
	}

	return outputResults(stdout, abs, results)
}
