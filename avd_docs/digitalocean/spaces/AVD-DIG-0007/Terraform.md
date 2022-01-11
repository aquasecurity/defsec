
Enable versioning to protect against accidental or malicious removal or modification

```hcl
resource "digitalocean_spaces_bucket" "good_example" {
  name   = "foobar"
  region = "nyc3"
  
  versioning {
    enabled = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#versioning
        