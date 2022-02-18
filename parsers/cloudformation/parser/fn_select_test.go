package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_select_value(t *testing.T) {

	source := `---
Parameters:
    EngineIndex:
      Type: Integer
      Default: 1
Resources:
	ElasticacheCluster:
	  Type: 'AWS::ElastiCache::CacheCluster'
	  Properties:    
	    Engine: !Select [ !Ref EngineIndex, [memcached, redis ]]
	    CacheNodeType: cache.t2.micro
	    NumCacheNodes: '1'
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("ElasticacheCluster")
	assert.NotNil(t, testRes)

	engineProp := testRes.GetProperty("Engine")
	require.True(t, engineProp.IsNotNil())
	require.True(t, engineProp.IsString())

	require.Equal(t, "redis", engineProp.AsString())
}
