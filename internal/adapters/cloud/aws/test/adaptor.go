package test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/elgohr/go-localstack"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var stack *localstack.Instance

func getOrCreateLocalStack(ctx context.Context, t *testing.T) (*localstack.Instance, error) {
	if stack == nil {
		_ = os.Setenv("DOCKER_API_VERSION", "1.41")

		envOpt, err := localstack.WithClientFromEnv()
		if err != nil {
			return nil, err
		}

		initScripts, err := localstack.WithInitScriptMount("../test/init-scripts", "Bootstrap Complete")
		if err != nil {
			return nil, err
		}

		buf := &concurrentWriter{buf: &bytes.Buffer{}}
		logger := log.New()
		logger.SetLevel(log.DebugLevel)
		logger.SetOutput(buf)

		stack, err = localstack.NewInstance(envOpt, initScripts, localstack.WithLogger(logger))
		if err != nil {
			return nil, err
		}

		err = stack.StartWithContext(ctx)
		if err != nil {
			return nil, err
		}

		// wait for ready
		for i := 1; i <= 10; i++ {
			if strings.Contains(string(buf.Bytes()), "Bootstrap Complete") {
				break
			}
			t.Logf("Waiting %d more second(s) for bootstrap to complete", i)
			time.Sleep(time.Duration(i) * time.Second)
			if i == 10 {
				t.Fail()
			}
		}
	}
	return stack, nil
}

func CreateLocalstackAdapter(t *testing.T, requiredService localstack.Service) (*aws2.RootAdapter, *localstack.Instance, error) {
	ctx := context.TODO()

	l, err := getOrCreateLocalStack(ctx, t)
	require.NoError(t, err)

	cfg, err := createTestConfig(ctx, l, requiredService)
	require.NoError(t, err)

	ra := aws2.NewRootAdapter(ctx, cfg, progress.NoProgress)
	require.NotNil(t, ra)
	return ra, stack, err
}

func createTestConfig(ctx context.Context, l *localstack.Instance, requiredService localstack.Service) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:       "aws",
				URL:               l.EndpointV2(requiredService),
				SigningRegion:     "us-east-1",
				HostnameImmutable: true,
			}, nil
		})),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "dummy")),
	)
}

type concurrentWriter struct {
	buf *bytes.Buffer
	mu  sync.RWMutex
}

func (c *concurrentWriter) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *concurrentWriter) Bytes() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.buf.Bytes()
}
