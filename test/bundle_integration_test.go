//go:build linux
// +build linux

package test

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var bundlePath = "bundle.tar.gz"
var OrasPush = []string{"--config", "/dev/null:application/vnd.cncf.openpolicyagent.config.v1+json", fmt.Sprintf("%s:application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", bundlePath)}

func createRegistryContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Helper()

	reqReg := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5111:5000/tcp"},
		WaitingFor:   wait.ForExposedPort(),
	}

	regC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqReg,
		Started:          true,
	})
	require.NoError(t, err)

	regIP, _ := regC.Host(ctx)
	fmt.Println(regIP)

	return regC, regIP
}

func createOrasContainer(t *testing.T, ctx context.Context, regIP string, bundlePath string) testcontainers.Container {
	t.Helper()

	reqOras := testcontainers.ContainerRequest{
		Image: "bitnami/oras:latest",
		Cmd:   append([]string{"push", fmt.Sprintf("%s:5111/defsec-test:latest", regIP)}, OrasPush...),
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: testcontainers.GenericBindMountSource{
					HostPath: filepath.Join(bundlePath),
				},
				Target: "/bundle.tar.gz",
			},
		},
		HostConfigModifier: func(config *container.HostConfig) {
			config.NetworkMode = "host"
		},
		WaitingFor: wait.ForLog("Pushed [registry] localhost:5111/defsec-test:latest"),
	}
	orasC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqOras,
		Started:          true,
	})
	require.NoError(t, err)

	return orasC
}

func createTrivyContainer(t *testing.T, ctx context.Context, regIP string) testcontainers.Container {
	t.Helper()

	reqTrivy := testcontainers.ContainerRequest{
		Image: "aquasec/trivy:latest",
		Cmd:   []string{"--debug", "config", fmt.Sprintf("--policy-bundle-repository=%s:5111/defsec-test:latest", regIP), "."},
		HostConfigModifier: func(config *container.HostConfig) {
			config.NetworkMode = "host"
		},
		WaitingFor: wait.ForLog("Policies successfully loaded from disk"),
	}
	trivyC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqTrivy,
		Started:          true,
	})
	require.NoError(t, err)

	return trivyC
}

func Test_Bundle(t *testing.T) {
	ctx := context.Background()

	bundlePath, err := filepath.Abs("bundle.tar.gz")
	require.NoError(t, err)

	regC, regIP := createRegistryContainer(t, ctx)
	defer func() {
		require.NoError(t, regC.Terminate(ctx))
	}()

	orasC := createOrasContainer(t, ctx, regIP, bundlePath)
	defer func() {
		require.NoError(t, orasC.Terminate(ctx))
	}()

	trivyC := createTrivyContainer(t, ctx, regIP)
	defer func() {
		require.NoError(t, trivyC.Terminate(ctx))
	}()

	// for debugging
	fmt.Println(debugLogsForContainer(t, ctx, regC))
	fmt.Println(debugLogsForContainer(t, ctx, orasC))
	fmt.Println(debugLogsForContainer(t, ctx, trivyC))
}

func debugLogsForContainer(t *testing.T, ctx context.Context, c testcontainers.Container) string {
	t.Helper()

	r, err := c.Logs(ctx)
	require.NoError(t, err)

	b, _ := io.ReadAll(r)
	return string(b)
}
