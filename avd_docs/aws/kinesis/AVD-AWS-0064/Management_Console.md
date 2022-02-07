1. Log into the AWS Management Console.
2. Select the "Services" option and search for "Kinesis". ![Step](/resources/aws/kinesis/kinesis-streams-encryption/step2.png)
3. Under the "Amazon Kinesis dashboard" choose "Data Firehose" from the left navigation panel. ![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step3.png)
4. Select the "Firehose Delivery System" that needs to be verified and click on the "Name" to access the delivery stream.![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step4.png)
5. Select the "Details" tab and scroll down to "Amazon S3 destination". Check the "Encryption" value and if it's set to "Disabled" then the selected "Firehose Delivery System" data is not encrypted. ![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step5.png)
6. Repeat steps number 4 and 5 to verify another "Firehose Delivery System".</br>
7. To enable the "Encryption" on selected "Firehose Delivery System" click on the "Name" to access the delivery stream. Under the "Details" tab click on the "Edit" button to make the changes in "Amazon S3 destination". ![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step7.png)
8. Click on the "Enable" button next to the "S3 encryption" to enable the encryption. ![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step8.png)
9. Choose the "KMS master key" from the dropdown list. Choose either the ("Default( aws/s3 )") KMS key or an AWS KMS Customer Master Key (CMK).![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step9.png)
10. Click on the "Save" button to make the necessary changes. On the successful configuration changes, one will get "Successfully updated delivery stream" message. ![Step](/resources/aws/kinesis/kinesis-streams-encrypted/step10.png)