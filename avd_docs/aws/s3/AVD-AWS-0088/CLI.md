1. Install awscli
```bash
pip3 install awscli
```

2. Configure `awscli`
```bash
aws configure
```

3. To enable bucket encryption on an S3 bucket called `unencrypted-bucket, run the following aws cli command

```bash
aws s3api put-bucket-encryption --bucket unencrypted-bucket --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
````
