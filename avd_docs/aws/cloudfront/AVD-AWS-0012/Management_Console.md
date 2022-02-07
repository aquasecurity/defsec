1. Log into the AWS Management Console.
2. Select the "Services" option and search for CloudFront. ![Step](/resources/aws/cloudfront/cloudfront-https-only/step2.png)
3. Select the "CloudFront Distribution" that needs to be verified.![Step](/resources/aws/cloudfront/cloudfront-https-only/step3.png)
4. Click the "Distribution Settings" button from menu to get into the "CloudFront Distribution" configuration page. ![Step](/resources/aws/cloudfront/cloudfront-https-only/step4.png)
5. Click the "Behaviors" button from the top menu to get into the "Behaviors" configuration page and select the "Behavior" which needs to be verified.![Step](/resources/aws/cloudfront/cloudfront-https-only/step5.png)
6. Click the "Edit" button from the "Behaviors" tab on the menu.![Step](/resources/aws/cloudfront/cloudfront-https-only/step6.png)
7. On the Default Cache Behavior Settings, verify the "Viewer Protocol Policy" and if "HTTP and HTTPS" is selected than CloudFront allows viewers to access your web content using either HTTP or HTTPS. ![Step](/resources/aws/cloudfront/cloudfront-https-only/step7.png)
8. On the "Viewer Protocol Policy" choose "Redirect HTTP to HTTPS" to redirect all HTTP requests to HTTPS.![Step](/resources/aws/cloudfront/cloudfront-https-only/step8.png)
9. On the "Viewer Protocol Policy" choose "HTTPS Only" so CloudFront allows viewers to access your content only if they're using HTTPS.![Step](/resources/aws/cloudfront/cloudfront-https-only/step9.png)
10. Repeat the steps number 5 , 6 and 7 to verify if any other CloudFront Distribution is using HTTP-only listeners.