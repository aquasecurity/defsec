
1. Log into the AWS Management Console.
2. Select the "Services" option and search for RDS. ![Step](/resources/aws/rds/rds-encryption-enabled/step2.png)
3. Scroll down the left navigation panel and choose "Databases". ![Step](/resources/aws/rds/rds-encryption-enabled/step3.png)
4. Select the "Database" that needs to be verified and click on the  selected "Databse" from the "DB identifier" column to access the database.![Step](/resources/aws/rds/rds-encryption-enabled/step4.png)
5. Click on the "Configuration" under the selected database configuration page.![Step](/resources/aws/rds/rds-encryption-enabled/step5.png)
6. Scroll down the "Configuration" tab and check the "Storage" section.Check the "Encryption" and if it's "Not Enabled" then encryption is not setup for selected RDS instance.![Step](/resources/aws/rds/rds-encryption-enabled/step6.png)
7. Repeat steps number 2 - 6 to check other RDS instances. </br>
8. Select the "Database" on which "Encryption" needs to be enabled.![Step](/resources/aws/rds/rds-encryption-enabled/step8.png)
9. Click on the "Actions" button at the top panel and click on "Take snapshot". ![Step](/resources/aws/rds/rds-encryption-enabled/step9.png)
10. On "Take DB Snapshot" page provide a "Snapshot name" which will act as an identifier for the "DB Snapshot" and click on "Take Snapshot" button.![Step](/resources/aws/rds/rds-encryption-enabled/step10.png)
11. Select the new created "Snapshot" and click on the "Actions" button at the top menu and click on the "Copy Snapshot" option.![Step](/resources/aws/rds/rds-encryption-enabled/step11.png)
12. Under the "Make Copy of DB Snapshot?" configuration page select the "Destination Region" and provide the "New DB Snapshot Identifier" for the new snapshot. ![Step](/resources/aws/rds/rds-encryption-enabled/step12.png)
13. Scroll down the "Make Copy of DB Snapshot?" configuration page and click on "Enable encryption" under Encryption section. Select the "Master key" from dropdown menu and click on the "Copy Snapshot" button.![Step](/resources/aws/rds/rds-encryption-enabled/step13.png)
14. Select the new created "Snapshot" and click on the "Actions" button at the top menu and click on the "Restore Snapshot" option.![Step](/resources/aws/rds/rds-encryption-enabled/step14.png)
15. On "Restore DB Instance" configuration page review all the configuration settings and provide a unique name to the "DB Instance" under "DB Instance Identifier".![Step](/resources/aws/rds/rds-encryption-enabled/step15.png)
16. Scroll down and click on the "Restore DB Instance" button. ![Step](/resources/aws/rds/rds-encryption-enabled/step16.png)
17. Update the "Database Endpoint" as soon as the new instance provisioning process is completed and the databse instance is available. ![Step](/resources/aws/rds/rds-encryption-enabled/step17.png)
18. Remoev the unencrypted database instance by selecting the database and clicking on the "Actions" button at the top menu and clicking on the "Delete" button under "Delete" panel. ![Step](/resources/aws/rds/rds-encryption-enabled/step18.png)
