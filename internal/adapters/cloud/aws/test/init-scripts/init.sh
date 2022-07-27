#!bin/bash

echo "########### Creating profile ###########"
aws configure set aws_access_key_id default_access_key --profile=localstack
aws configure set aws_secret_access_key default_secret_key --profile=localstack
aws configure set region us-east-1 --profile=localstack

echo "########### Listing profile ###########"
aws configure list --profile=localstack

echo "########### Creating Access Log Bucket ###########"
aws s3api create-bucket --endpoint-url=http://localhost:4566 --profile=localstack --bucket access-logs
aws s3api put-bucket-acl --endpoint-url=http://localhost:4566 --profile=localstack --bucket access-logs --acl log-delivery-write





# Init script MUST end with Bootstrap Complete - DO NOT EDIT BELOW THIS LINE
echo "########### Bootstrap Complete ###########"