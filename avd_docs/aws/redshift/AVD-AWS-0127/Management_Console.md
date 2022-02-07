1. Log into the AWS Management Console.
2. Select the "Services" option and search for Redshift. ![Step](/resources/aws/redshift/redshift-publicly-accessible/step2.png)
3. Scroll down the left navigation panel and choose "Clusters". ![Step](/resources/aws/redshift/redshift-publicly-accessible/step3.png)
4. Select the "Cluster" that needs to be verified and click on its identifier(name) from the "Cluster" column.![Step](/resources/aws/redshift/redshift-publicly-accessible/step4.png)
5. Scroll down the "Cluster" configuration page and check the "Publicly Accessible" option under the "Cluster Database Properties". If current status is set to "Yes" then the selected cluster is launched into the public cloud.![Step](/resources/aws/redshift/redshift-publicly-accessible/step5.png)
6. Repeat steps number 2 - 5 to verify other clusters. </br>
7. Select the "Cluster" on which "Public Accessibility" needs to be disable.Click on its identifier(name)from the "Cluster" column to go into "Cluster" configuration page.![Step](/resources/aws/redshift/redshift-publicly-accessible/step7.png)
8. Click on the "Cluster" dropdown button at the top menu and click on the "Modify Cluster" option.![Step](/resources/aws/redshift/redshift-publicly-accessible/step8.png)
9. On the "Modify Cluster" page select the "No" option next to "Publicly accessible" under "Cluster Settings". Click on the "Modify" button to make the necessary changes.![Step](/resources/aws/redshift/redshift-publicly-accessible/step9.png)
10. Repeat steps number 7 - 9 to disable "Public Accessibility" for other clusters.</br> 
