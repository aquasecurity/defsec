1. Log into the AWS Management Console.
2. Select the "Services" option and search for IAM. ![Step](/resources/aws/iam/users-mfa-enabled/step2.png)
3. Scroll down the left navigation panel and choose "Users". ![Step](/resources/aws/iam/users-mfa-enabled/step3.png)
4. Select the "User" that needs to be verified and click on the "User name" to access the selected "IAM User".![Step](/resources/aws/iam/users-mfa-enabled/step4.png)
5. Click on the "Security Credentials" under the configuration page.![Step](/resources/aws/iam/users-mfa-enabled/step4.png)
6. Scroll down the "Security Credentials" tab and check the "Assigned MFA device".Check the "Multi-factor authentication (MFA)" section for any active devices. If "Not assigned " is showing against "Assigned MFA device" than a multi-factor authentication device is not enabled for the selected user account.![Step](/resources/aws/iam/users-mfa-enabled/step6.png)
7. Repeat steps number 2 - 6 to check another IAM user.</br>
8. On "Your Security Credentials" page scroll down and click on the "Multi-factor authentication (MFA)" and click on the "Manage" link to enable a multi-factor authentication device.![Step](/resources/aws/iam/users-mfa-enabled/step8.png)
9. Click on the "Virtual MFA device" and click on "Continue". ![Step](/resources/aws/iam/users-mfa-enabled/step9.png)
10. Now install the AWS MFA compatible application on mobile device or computer. Once the application is installed click on the "Show QR code" and scan the code with pre-installed application.![Step](/resources/aws/iam/users-mfa-enabled/step10.png)
11. Enter two consecutive MFA codes generated from application in "MFA code 1" and "MFA code 2" and click on the "Assign MFA" button.![Step](/resources/aws/iam/users-mfa-enabled/step11.png)
12. On successful setup will get the following message "You have successfully assigned virtual MFA". ![Step](/resources/aws/iam/users-mfa-enabled/step12.png)
13. Repeat steps number 8 - 12 to enable multi-factor authentication device for all other IAM users. 