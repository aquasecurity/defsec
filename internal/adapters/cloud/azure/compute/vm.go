// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package compute

import (
	"context"
	"github.com/Azure-Samples/azure-sdk-for-go-samples/services/internal/config"
	"github.com/Azure-Samples/azure-sdk-for-go-samples/services/internal/iam"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
)

func getVMClient() compute.VirtualMachinesClient {
	vmClient := compute.NewVirtualMachinesClient(config.SubscriptionID())
	a, _ := iam.GetResourceManagementAuthorizer()
	vmClient.Authorizer = a
	_ = vmClient.AddToUserAgent(config.UserAgent())
	return vmClient
}

func getVMExtensionsClient() compute.VirtualMachineExtensionsClient {
	extClient := compute.NewVirtualMachineExtensionsClient(config.SubscriptionID())
	a, _ := iam.GetResourceManagementAuthorizer()
	extClient.Authorizer = a
	_ = extClient.AddToUserAgent(config.UserAgent())
	return extClient
}

// GetVM gets the specified VM info
func GetVM(ctx context.Context, vmName string) (compute.VirtualMachine, error) {
	vmClient := getVMClient()
	return vmClient.Get(ctx, config.GroupName(), vmName, compute.InstanceView)
}
