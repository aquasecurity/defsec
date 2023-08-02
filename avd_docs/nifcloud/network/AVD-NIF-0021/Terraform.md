
Switch to HTTPS to benefit from TLS security features

```hcl
 resource "nifcloud_elb" "good_example" {
     protocol = "HTTPS"
 }
 
```
```hcl
resource "nifcloud_load_balancer" "good_example" {
    load_balancer_port = 443
}

```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol

 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port

