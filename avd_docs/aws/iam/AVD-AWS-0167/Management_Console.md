1. Sign in to the AWS Management Console and navigate to IAM dashboard at https://console.aws.amazon.com/iam/.
2. In the left navigation panel, choose Users.
3. Click on the IAM user name that you want to examine.
4. On the IAM user configuration page, select Security Credentials tab.
5. In Access Keys section, choose one access key that is less than 90 days old. This should be the only active key used by this IAM user to access AWS resources programmatically. Test your application(s) to make sure that the chosen access key is working.
6. In the same Access Keys section, identify your non-operational access keys (other than the chosen one) and deactivate it by clicking the Make Inactive link.
7. If you receive the Change Key Status confirmation box, click Deactivate to switch off the selected key.