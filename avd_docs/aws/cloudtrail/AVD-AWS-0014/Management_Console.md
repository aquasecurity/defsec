1. Log into the AWS Management Console.
2. Select the "Services" option and search for "CloudTrail".![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step2.png)
3. In the "Dashboard" panel click on "View trails" button.![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step3.png)
4. Select the "trail" that needs to be verified under "Name" column.![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step4.png)
5. Click the pencil icon to go into "Trail Settings" and verify the checkbox marked against "Apply trail to all regions
". If "No" is selected than create and manage a trail across all regions is not possible.![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step5.png)
6. Go to "Trail Settings" and click on "Yes" checkbox to enable the "Apply trail to all regions" which receive the log files containing event history for the new region without taking any action. Click on the "Save" button to make the changes. ![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step6.png)
7. Scroll down and go to "Additional Configuration" settings and click on the pencil icon to make the changes.![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step7.png)
8. Click on the "Yes" checkbox corresponding to the "Include global services" and click on "Save" button to make the changes.![Step](/resources/aws/cloudtrail/cloudtrail-enabled/step8.png)
9. CloudTrail is enabled for all regions with global service events now.