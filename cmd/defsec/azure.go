package main

//
//import (
//	"context"
//	"io"
//
//	"github.com/aquasecurity/defsec/pkg/framework"
//
//	"github.com/aquasecurity/defsec/pkg/scanners/cloud/azure"
//
//	"github.com/spf13/cobra"
//
//	"github.com/aquasecurity/defsec/pkg/scanners/options"
//)
//
//func init() {
//	azureCmd := &cobra.Command{
//		Use:   "azure",
//		Short: "Scan an Azure account for misconfigurations",
//		Args:  cobra.ExactArgs(0),
//		RunE: func(cmd *cobra.Command, args []string) error {
//			cmd.SilenceUsage = true
//			cmd.SilenceErrors = true
//			return scanAzure(cmd.OutOrStdout(), cmd.ErrOrStderr())
//		},
//	}
//	azureCmd.Flags().StringVarP(&flagAzureFramework, "framework", "k", flagAzureFramework, "framework to use (default, all)")
//	azureCmd.Flags().StringVarP(&flagAzureRegion, "region", "r", flagAzureRegion, "Azure region to scan")
//	azureCmd.Flags().StringSliceVarP(&flagAzureServices, "services", "s", flagAzureServices, "Azure services to scan")
//	rootCmd.AddCommand(azureCmd)
//}
//
//var (
//	flagAzureRegion    = "eastus"
//	flagAzureServices  []string
//	flagAzureFramework = string(framework.Default)
//)
//
//func scanAzure(stdout, stderr io.Writer) error {
//
//	opts := []options.ScannerOption{
//		options.ScannerWithEmbeddedPolicies(true),
//	}
//
//	if flagDebug {
//		opts = append(opts, options.ScannerWithDebug(stderr))
//	}
//
//	if flagAzureRegion != "" {
//		opts = append(opts, azure.ScannerWithAzureRegion(flagAzureRegion))
//	}
//
//	if len(flagAzureServices) > 0 {
//		opts = append(opts, azure.ScannerWithAzureServices(flagAzureServices...))
//	}
//
//	opts = append(opts, options.ScannerWithFrameworks(framework.Framework(flagAzureFramework)))
//
//	scanner := azure.New(opts...)
//
//	st, err := scanner.CreateState(context.TODO())
//	if err != nil {
//		return err
//	}
//
//	// Execute the filesystem based scanners
//	results, err := scanner.Scan(context.TODO(), st)
//	if err != nil {
//		return err
//	}
//
//	return outputResults(stdout, ".", results)
//}
