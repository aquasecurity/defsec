1. Log into the AWS Management Console.
2. Select the "Services" option and search for IAM. ![Step](/resources/aws/iam/password-reuse-prevention/step2.png)
3. Scroll down the left navigation panel and choose "Account Settings". ![Step](/resources/aws/iam/password-reuse-prevention/step3.png)
4. Under the "Password Policy" configuration panel scroll down and check the "Prevent password reuse ". If the checkbox is not selected than the password policy does not  prevents the reuse of password.![Step](/resources/aws/iam/password-reuse-prevention/step4.png)
5. Repeat steps number 3 and 4 to prevent reuse of password .</br>
6. Click on the checkbox next to "Prevent password reuse" so "Password Policy" prevents reuse of the older passwords. Enter the "Number of passwords to remember" to 24 . ![Step](/resources/aws/iam/password-reuse-prevention/step6.png)
7. Click on the "Apply Password Policy" button to make the necessary changes.![Step](/resources/aws/iam/password-reuse-prevention/step7.png)