
Set a more restrictive CIRDR range

```hcl
resource "digitalocean_firewall" "good_example" {
  name = "only-22-80-and-443"
  
  droplet_ids = [digitalocean_droplet.web.id]
  
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["192.168.1.0/24", "fc00::/7"]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall
        