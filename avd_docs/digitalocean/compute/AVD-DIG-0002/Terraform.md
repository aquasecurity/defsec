
Switch to HTTPS to benefit from TLS security features

```hcl
 resource "digitalocean_loadbalancer" "bad_example" {
   name   = "bad_example-1"
   region = "nyc3"
   
   forwarding_rule {
 	entry_port     = 443
 	entry_protocol = "https"
   
 	target_port     = 443
 	target_protocol = "https"
   }
   
   droplet_ids = [digitalocean_droplet.web.id]
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer

