
Set a more restrictive cidr range

```hcl
resource "digitalocean_firewall" "good_example" {
  name = "only-22-80-and-443"
  
  droplet_ids = [digitalocean_droplet.web.id]
  
  outbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    destination_addresses = ["192.168.1.0/24", "fc00::/7"]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall
        