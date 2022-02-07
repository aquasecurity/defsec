1. Log into the AWS Management Console.
2. Select the "Services" option and search for "CloudTrail".![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step2.png)
3. In the "Dashboard" panel click on "View trails" button.![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step3.png)
4. Select the "trail" that needs to be verified under "Name" column.![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step4.png)
5. Scroll down and under the "Storage location" option check for "Enable log file validation". If its status is "No" the selected trail does not support file validation.![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step5.png)
6. Click on the pencil icon to get into "Storage location" configuration settings. Scroll down and click on "Yes" next to "Enable log file validation" to enable the "CloudTrail" file validation to determine whether a log file was modified, deleted or unchanged after "CloudTrail" delivered it. ![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step6.png)
7. Scroll down and click on "Save" to enable the CloudTrail log encryption.![Step](/resources/aws/cloudtrail/cloudtrail-file-validation/step7.png)
