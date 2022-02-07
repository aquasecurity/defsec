1. Log into the AWS Management Console.
2. Select the "Services" option and search for SQS. ![Step](/resources/aws/sqs/sqs-encrypted/step2.png)
3. Select the "SQS" queue that needs to be verify from "Name".![Step](/resources/aws/sqs/sqs-encrypted/step3.png)
4. Scroll down the page and click on the "Encryption" tab from the bottom panel.![Step](/resources/aws/sqs/sqs-encrypted/step4.png)
5. Check the "Server Side Encryption" status for the selected "SQS" queue. If the "Server Side Encryption" is not configured then the following message is being displayed "Server-side encryption (SSE) is disabled. SSE lets you protect the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS)".![Step](/resources/aws/sqs/sqs-encrypted/step5.png)
6. Repeat steps number 2 - 5 to verify other "SQS" queue in the selected AWS region.</br>
7. To enable the "SQS" encryption navigate to KMS services to create a "KMS CMK customer-managed key".![Step](/resources/aws/sqs/sqs-encrypted/step7.png)
8. Scroll down the left navigation panel and choose "Customer managed keys" under "Key Management Service" and click on the "Create key" button at the top panel.![Step](/resources/aws/sqs/sqs-encrypted/step8.png)
9. On the "Add alias and description" page provide the "Alias" and "Description" for the new "KMS key" and click on the "Next" button. ![Step](/resources/aws/sqs/sqs-encrypted/step9.png)
10. On the "Add tags" page provide a unique key for "Tag key", "Tag value" and click on the "Next" button.![Step](/resources/aws/sqs/sqs-encrypted/step10.png)
11. On the "Define key administrative permissions" page select the "IAM users" and roles who can administer the new "KMS key" through the KMS API.![Step](/resources/aws/sqs/sqs-encrypted/step11.png)
12. Click on the "Next" button at the bottom to continue the new "KMS key" process. ![Step](/resources/aws/sqs/sqs-encrypted/step12.png)
13. On the "Define key usage permissions" page select the IAM users and roles that can use the CMK to encrypt and decrypt SQS data with the "AWS KMS API" and click on the "Next" button.![Step](/resources/aws/sqs/sqs-encrypted/step13.png)
14.  On the "Review and edit key policy" page review the policy and click on the "Finish" button to create a new "KMS key" which can be used to encrypt/decrypt the SQS data.![Step](/resources/aws/sqs/sqs-encrypted/step14.png)
15. Now "KMS CMK customer-managed key" is created navigate to SQS and select the "SQS" queue which needs to be modified.![Step](/resources/aws/sqs/sqs-encrypted/step15.png)
16. Click on the "Queue Actions" button at the top and select the "Configure Queue" option. ![Step](/resources/aws/sqs/sqs-encrypted/step16.png)
17. On the "Configure Test" tab scroll down and under the "Server-Side Encryption (SSE) Settings" click on the checkbox next to "Use SSE" and select the "AWS KMS Customer Master Key (CMK)" from the dropdown menu and click on the "Save Changes" button to make the necessary changes.![Step](/resources/aws/sqs/sqs-encrypted/step17.png)
18. Repeat steps number 8 - 17 to enable encryption using KMS for all SQS queues.