1. Log into the AWS Management Console.
2. Select the "Services" option and search for IAM. ![Step](/resources/aws/iam/maximum-password-age/step2.png)
3. Scroll down the left navigation panel and choose "Account Settings". ![Step](/resources/aws/iam/maximum-password-age/step3.png)
4. Under the "Password Policy" configuration panel scroll down and check the "Enable password expiration". If the "Enable password expiration" checkbox is not ticked then the password won't reset in any number of days. ![Step](/resources/aws/iam/maximum-password-age/step4.png)
5. If the "Enable password expiration" checkbox is ticked and "Password expiration period (in days)" is set to above 180 days than the allowed age of password might lead to a security threat as the same password will be active for a long period of time.![Step](/resources/aws/iam/maximum-password-age/step5.png)
6. Click on the "Enable password expiration" checkbox and mention the 180 days under "Password expiration period (in days)" so that the password will be expired after 180days. After 180 days, the password expires and the IAM user must set a new password before accessing the AWS Management Console.![Step](/resources/aws/iam/maximum-password-age/step6.png)
7. Click on the "Apply Password Policy" button to make the necessary changes.![Step](/resources/aws/iam/maximum-password-age/step7.png)

