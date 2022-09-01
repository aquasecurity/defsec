package bigquery

var terraformDatasetEncryptionCustomerKeyGoodExamples = []string{
	`
resource "google_bigquery_dataset" "good_example" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    user_by_email = google_service_account.bqowner.email
  }

  access {
    role   = "READER"
    domain = "hashicorp.com"
  }

  default_encryption_configuration {
    kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
  }
}
`,
}

var terraformDatasetEncryptionCustomerKeyBadExamples = []string{
	`
resource "google_bigquery_dataset" "bad_example" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }

  access {
    role   = "READER"
    domain = "hashicorp.com"
  }
}
`,
}

var terraformDatasetEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_dataset#nested_default_encryption_configuration`,
}

var terraformDatasetEncryptionCustomerKeyRemediationMarkdown = ``
