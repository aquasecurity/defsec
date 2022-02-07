1. Log into the AWS Management Console.
2. Select the "Services" option and search for EC2. ![Step](/resources/aws/elb/insecure-ciphers/step2.png)
3. In the "EC2 Dashboard" scroll down and look for "Load Balancers" and click on "Load Balancers" to get into "Load Balancers" dashboard.![Step](/resources/aws/elb/insecure-ciphers/step3.png)
4. Select the "Load Balancer" which needs to be verified. ![Step](/resources/aws/elb/insecure-ciphers/step4.png)
5. Select the "Listeners" tab from the bottom panel and scroll down to the "Cipher" column of HTTPS Listener and click on "Change" option.![Step](/resources/aws/elb/insecure-ciphers/step5.png)
6. From "Select a Cipher" panel select either of "Predefined Security Policy" and "Custom Security Policy".![Step](/resources/aws/elb/insecure-ciphers/step6.png)
7. Scan the "SSL Cipher Section" from selected "Security Policy" for any insecure ciphers. Refer to the link for all secure ciphers. https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html#ssl-ciphers ![Step](/resources/aws/elb/insecure-ciphers/step7.png)
8. Scroll down and click on "Save" button to make the changes. ![Step](/resources/aws/elb/insecure-ciphers/step8.png)
