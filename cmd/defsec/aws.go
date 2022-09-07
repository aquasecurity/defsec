package main

import (
	"context"
	"io"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scanners/aws/cloud"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

func init() {
	awsCmd := &cobra.Command{
		Use:   "aws",
		Short: "Scan an AWS account for misconfigurations",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return scanAWS(cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	awsCmd.Flags().StringVarP(&flagFramework, "framework", "k", flagFramework, "framework to use (default, all, cis-aws-1.2, cis-aws-1.4)")
	awsCmd.Flags().StringVarP(&flagAWSRegion, "region", "r", flagAWSRegion, "AWS region to scan")
	awsCmd.Flags().StringSliceVarP(&flagAWSServices, "services", "s", flagAWSServices, "AWS services to scan")
	rootCmd.AddCommand(awsCmd)
}

var (
	flagAWSRegion   = "us-east-1"
	flagAWSServices []string
	flagFramework   = string(framework.Default)
)

func scanAWS(stdout, stderr io.Writer) error {

	opts := []options.ScannerOption{
		options.ScannerWithEmbeddedPolicies(true),
	}

	if flagDebug {
		opts = append(opts, options.ScannerWithDebug(stderr))
	}

	if flagAWSRegion != "" {
		opts = append(opts, cloud.ScannerWithAWSRegion(flagAWSRegion))
	}

	if len(flagAWSServices) > 0 {
		opts = append(opts, cloud.ScannerWithAWSServices(flagAWSServices...))
	}

	opts = append(opts, options.ScannerWithFrameworks(framework.Framework(flagFramework)))

	scanner := cloud.New(opts...)

	// Execute the filesystem based scanners
	results, err := scanner.Scan(context.TODO())
	if err != nil {
		return err
	}

	return outputResults(stdout, ".", results)
}
