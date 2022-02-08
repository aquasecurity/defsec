1. Log into the AWS Management Console.
2. Select the "Services" option and search for "CloudTrail".![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step2.png)
3. In the "Dashboard" panel click on "View trails" button.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step3.png)
4. Select the "trail" that needs to be verified under "Name" column.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step4.png)
5. Scroll down and under the "Storage location" option check for "Encrypt log files with SSE-KMS". If its status is "No" the selected trail does not support log encryption.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step5.png)
6. Click on the pencil icon to get into "Storage location" configuration settings. Scroll down and click on "Yes" next to "Encrypt log files with SSE-KMS" to enable the "CloudTrail" log encryption. ![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step6.png)
7. Click on the "Yes" option next to "Create a new KMS key" and enter a name. Make sure KMS key and S3 bucket must be in the same region.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step7.png)
8. Click on "No" option next to "Create a new KMS key" if already have "KMS key" available.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step8.png)
9. Scroll down and click on "Save" to enable the CloudTrail log encryption.![Step](/resources/aws/cloudtrail/cloudtrail-encryption/step9.png)
