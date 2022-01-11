
Disable legacy metadata endpoints

```hcl
resource "google_container_cluster" "good_example" {
  metadata {
    disable-legacy-endpoints = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata
        