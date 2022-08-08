1. Log into the AWS Management Console.
2. Select the "Services" option and search for "CloudTrail".</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step2.png"/>
3. In the "Dashboard" panel click on "View trails" button.</br> <img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step3.png"/>
4. Select the "trail" that needs to be verified under "Name" column.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step4.png"/>
5. Scroll down and under the "Storage location" option check the S3 bucket used to store log data.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step5.png"/>
6. Go to "Services" and search for "S3" to go into S3 buckets dashboard.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step6.png"/>
7. Select the "S3 bucket" used to store data log in CloudTrail and check the "Access" option. If "Access" shows "Public" than bucket is publicly accessible </br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step7.png"/>
8. Click on "Edit Public Access Settings" to configure the S3 Bucket access. </br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step8.png"/>
9. Click on the checkboxes shown under "Manage public Access control lists (ACLs)" and "Manage public bucket policies" to make the S3 bucket private.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step9.png"/>
10. Select the "S3 bucket" used by CloudTrail and click on "Permissions" tab.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step10.png"/>
11. Select the "Access Control List" from the menu and search for any group with the name "Everyone" and make sure this group has no checkboxes enabled. If this group has one or more checkboxes enabled than the selected S3 bucket is publicly accessible. </br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step11.png"/>
12. Check the "Access for other AWS accounts" on the selected S3 bucket for known users.</br><img src="/resources/aws/cloudtrail/cloudtrail-bucket-private/step12.png"/>
13. S3 buckets access policy for all "CloudTrail buckets" have access allow only to known users now. 
