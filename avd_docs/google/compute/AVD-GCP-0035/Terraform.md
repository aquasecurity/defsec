
Set a more restrictive cidr range

```hcl
 resource "google_compute_firewall" "good_example" {
  direction = "EGRESS"
  allow {
    protocol = "icmp"
  }
  destination_ranges = ["1.2.3.4/32"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall

