package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elb.ELB
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_alb" "example" {
				name               = "good_alb"
				internal           = true
				load_balancer_type = "application"
				
				access_logs {
				  bucket  = aws_s3_bucket.lb_logs.bucket
				  prefix  = "test-lb"
				  enabled = true
				}
			  
				drop_invalid_header_fields = true
			  }

			  resource "aws_alb_listener" "example" {
				load_balancer_arn = aws_alb.example.arn
				protocol = "HTTPS"
				ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"

				default_action {
					type             = "forward"
				}
			}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                types.NewTestMetadata(),
						Type:                    types.String("application", types.NewTestMetadata()),
						DropInvalidHeaderFields: types.Bool(true, types.NewTestMetadata()),
						Internal:                types.Bool(true, types.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata:  types.NewTestMetadata(),
								Protocol:  types.String("HTTPS", types.NewTestMetadata()),
								TLSPolicy: types.String("ELBSecurityPolicy-TLS-1-1-2017-01", types.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: types.NewTestMetadata(),
										Type:     types.String("forward", types.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_alb" "example" {
			}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                types.NewTestMetadata(),
						Type:                    types.String("application", types.NewTestMetadata()),
						DropInvalidHeaderFields: types.Bool(false, types.NewTestMetadata()),
						Internal:                types.Bool(false, types.NewTestMetadata()),
						Listeners:               nil,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_alb" "example" {
		name               = "good_alb"
		internal           = true
		load_balancer_type = "application"
		drop_invalid_header_fields = true
		
		access_logs {
		  bucket  = aws_s3_bucket.lb_logs.bucket
		  prefix  = "test-lb"
		  enabled = true
		}
	  }

	  resource "aws_alb_listener" "example" {
		load_balancer_arn = aws_alb.example.arn
		protocol = "HTTPS"
		ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"

		default_action {
			type             = "forward"
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.LoadBalancers, 1)
	loadBalancer := adapted.LoadBalancers[0]

	assert.Equal(t, 2, loadBalancer.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, loadBalancer.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, loadBalancer.Internal.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, loadBalancer.Internal.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, loadBalancer.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, loadBalancer.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, loadBalancer.DropInvalidHeaderFields.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, loadBalancer.DropInvalidHeaderFields.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, loadBalancer.Listeners[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, loadBalancer.Listeners[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, loadBalancer.Listeners[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, loadBalancer.Listeners[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, loadBalancer.Listeners[0].TLSPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, loadBalancer.Listeners[0].TLSPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, loadBalancer.Listeners[0].DefaultActions[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, loadBalancer.Listeners[0].DefaultActions[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, loadBalancer.Listeners[0].DefaultActions[0].Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, loadBalancer.Listeners[0].DefaultActions[0].Type.GetMetadata().Range().GetEndLine())

}
