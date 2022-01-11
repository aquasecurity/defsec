
Enable encryption for CodeBuild project artifacts

```hcl
resource "aws_codebuild_project" "good_example" {
  // other config
  
  artifacts {
    // other artifacts config
    
    encryption_disabled = false
  }
}

resource "aws_codebuild_project" "good_example" {
  // other config
  
  artifacts {
    // other artifacts config
  }
}

resource "aws_codebuild_project" "codebuild" {
  // other config
  
  secondary_artifacts {
    // other artifacts config
    
    encryption_disabled = false
  }
  
  secondary_artifacts {
    // other artifacts config
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled
        