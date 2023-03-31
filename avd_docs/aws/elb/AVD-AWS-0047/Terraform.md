
Use a more recent TLS/SSL policy for the load balancer

```hcl
 resource "aws_alb_listener" "good_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
 	protocol = "HTTPS"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener

