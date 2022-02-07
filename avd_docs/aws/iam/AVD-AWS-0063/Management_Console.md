1. Log into the AWS Management Console.
2. Select the "Services" option and search for IAM. ![Step](/resources/aws/iam/minimum-password-length/step2.png)
3. Scroll down the left navigation panel and choose "Account Settings". ![Step](/resources/aws/iam/minimum-password-length/step3.png)
4. Under the "Password Policy" configuration panel scroll down and check the "Minimum Password Length". If the password length is set less than 8 characters than the password security is at risk. ![Step](/resources/aws/iam/minimum-password-length/step4.png)
5. Click on the "Minimum Password Length" checkbox and mention the minimum characters required to 14. Click the checkbox against "Require at least one uppercase letter" and "Require at least one lowercase letter" to make the password more secure. ![Step](/resources/aws/iam/minimum-password-length/step5.png)
6. Click on the "Apply Password Policy" button to make the necessary changes.![Step](/resources/aws/iam/minimum-password-length/step6.png)
7. Now "Password Policy" requires at least 14 characters with one uppercase and one lowercase character for a strong and secure password.