---
additional_links: 
  - "https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#force_destroy"
---

Don't use force destroy on bucket configuration

```hcl
resource "digitalocean_spaces_bucket" "good_example" {
   name   = "foobar"
   region = "nyc3"
 }
```
