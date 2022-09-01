package bigquery

var terraformTableEncryptionCustomerKeyGoodExamples = []string{
	`
resource "google_bigquery_table" "default" {
  dataset_id = "my-dataset-id"
  table_id   = "bar"

  encryption_configuration {
    kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
  }
}
`,
}

var terraformTableEncryptionCustomerKeyBadExamples = []string{
	`
resource "google_bigquery_table" "default" {
  dataset_id = "my-dataset-id"
  table_id   = "bar"
}
`,
}

var terraformTableEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_table#nested_encryption_configuration`,
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_dataset#nested_default_encryption_configuration`,
}

var terraformTableEncryptionCustomerKeyRemediationMarkdown = ``
