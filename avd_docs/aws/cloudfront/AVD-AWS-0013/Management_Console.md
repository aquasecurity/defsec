1. Log into the AWS Management Console.
2. Select the "Services" option and search for CloudFront. ![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step2.png)
3. Select the "CloudFront Distribution" that needs to be verified.![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step3.png)
4. Click the "Distribution Settings" button from menu to get into the "CloudFront Distribution" configuration page. ![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step4.png)
5. Click the "Edit" button from the  General tab on the top menu. ![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step5.png)
6. Scroll down and choose the "Security Policy" that you want CloudFront to use for HTTPS connections and must use TLSv1.1 or higher SSL protocols.![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step6.png)
7. Scroll down and click on "Yes,Edit" to save the changes.![Step](/resources/aws/cloudfront/insecure-cloudfront-protocols/step7.png)
8. Repeat the steps number 5 and 6 to establish any other "CloudFront Distribution" is not using an insecure SSL protocol for HTTPS traffic.