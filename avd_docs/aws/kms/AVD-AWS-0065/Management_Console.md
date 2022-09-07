1. Login to the AWS Management Console.
2. Select the "Services" option and search for KMS. ![Step](/resources/aws/kms/kms-key-rotation/step2.png)
3. Scroll down the left navigation panel and choose "Customer Managed Keys" under "Key Management Service".![Step](/resources/aws/kms/kms-key-rotation/step3.png)
4. Select the key that needs to be verified by clicking on the alias of the key under "Alias".![Step](/resources/aws/kms/kms-key-rotation/step4.png)
5. Scroll down the "Customer managed keys" page and click on the "Key rotation" and check the "Automatically rotate this CMK every year" status. If it's not checked then the selected "KMS key" is not set to rotate on a regular schedule.![Step](/resources/aws/kms/kms-key-rotation/step5.png)
6. Repeat steps number 2 - 5 to verify other "KMS keys" in the selected AWS region.</br>
7. Navigate to "Customer Managed Keys" under "Key Management Service" and select the "KMS key" that needs to modify to enable yearly rotation for the KMS key.![Step](/resources/aws/kms/kms-key-rotation/step7.png)
8. Scroll down the "Customer managed keys" page and click on the "Key rotation" tab. Enable "Automatically rotate this CMK every year" checkbox and click on the "Save" button to make the necessary changes.![Step](/resources/aws/kms/kms-key-rotation/step8.png)
9. Repeat steps number 7 - 8 to enable yearly rotation for the "KMS key".</br>
