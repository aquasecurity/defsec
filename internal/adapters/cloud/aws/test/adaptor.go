package test

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/progress"
	localstack "github.com/aquasecurity/go-mock-aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func getOrCreateLocalStack(ctx context.Context) (*localstack.Stack, error) {
	_ = os.Setenv("DOCKER_API_VERSION", "1.41")
	stack := localstack.New()

	initScripts, err := localstack.WithInitScriptMount(
		"../test/init-scripts",
		"Bootstrap Complete")
	if err != nil {
		return nil, err
	}

	buf := &concurrentWriter{buf: &bytes.Buffer{}}
	logger := log.New()
	logger.SetLevel(log.DebugLevel)
	logger.SetOutput(buf)

	err = stack.Start(false, initScripts, localstack.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return stack, nil
}

func CreateLocalstackAdapter(t *testing.T) (*aws2.RootAdapter, *localstack.Stack, error) {
	ctx := context.Background()
	l, err := getOrCreateLocalStack(ctx)
	require.NoError(t, err)

	cfg, err := createTestConfig(ctx, l)
	require.NoError(t, err)

	ra := aws2.NewRootAdapter(ctx, cfg, progress.NoProgress)
	require.NotNil(t, ra)
	return ra, l, err
}

func createTestConfig(ctx context.Context, l *localstack.Stack) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:       "aws",
				SigningRegion:     "us-east-1",
				URL:               l.EndpointURL(),
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
