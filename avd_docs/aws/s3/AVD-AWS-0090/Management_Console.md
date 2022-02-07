1. Log into the AWS Management Console.
2. Select the "Services" option and search for S3. ![Step](/resources/aws/s3/s3-bucket-versioning/step2.png)
3. Scroll down the left navigation panel and choose "Buckets".![Step](/resources/aws/s3/s3-bucket-versioning/step3.png)
4. Select the "Bucket" that needs to be verified and click on its identifier(name) from the "Bucket name" column.![Step](/resources/aws/s3/s3-bucket-versioning/step4.png)
5. Click on the "Properties" tab on the top menu. ![Step](/resources/aws/s3/s3-bucket-versioning/step5.png)
6. Check the "Versioning" option under "Properties" and if it's set to "Suspend versioning" then S3 bucket versioning is not enabled for the selected S3 bucket. ![Step](/resources/aws/s3/s3-bucket-versioning/step6.png)
7. Repeat steps number 2 - 6 to verify other S3 buckets in the region. </br>
8. Select the "S3 bucket" on which versioning needs to be enabled and click on the "Properties" tab. ![Step](/resources/aws/s3/s3-bucket-versioning/step8.png)
9. Click on the "Enable versioning" option under "Versioning".![Step](/resources/aws/s3/s3-bucket-versioning/step9.png)
10. Click on the "Save" button to make the necessary changes. ![Step](/resources/aws/s3/s3-bucket-versioning/step10.png)
11. Repeat steps number 8 - 10 to enable versioning for other S3 buckets.