
Set a more restrictive cidr range

```hcl
resource "google_compute_firewall" "good_example" {
  source_ranges = ["1.2.3.4/32"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges
 - https://www.terraform.io/docs/providers/google/r/compute_firewall.html
        