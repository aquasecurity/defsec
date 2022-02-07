1. Log into the AWS Management Console.
2. Select the "Services" option and search for Redshift. ![Step](/resources/aws/redshift/redshift-encryption-enabled/step2.png)
3. Scroll down the left navigation panel and choose "Clusters". ![Step](/resources/aws/redshift/redshift-encryption-enabled/step3.png)
4. Select the "Cluster" that needs to be verified and click on its identifier(name) from the "Cluster" column.![Step](/resources/aws/redshift/redshift-encryption-enabled/step4.png)
5. Scroll down the "Cluster" configuration page and check the "Encrypted" option under the "Cluster Database Properties". If current status is set to "No" then the data stored on the cluster is not encrypted.![Step](/resources/aws/redshift/redshift-encryption-enabled/step5.png)
6. Repeat steps number 2 - 5 to verify other clusters. </br>
7. Scroll down the left navigation panel and choose "Clusters" and click on "Quick launch cluster" button at the top menu to start a new cluster process. ![Step](/resources/aws/redshift/redshift-encryption-enabled/step7.png)
8. Select the "Node type" from the dropdown menu and select the number of "Nodes" in the cluster.![Step](/resources/aws/redshift/redshift-encryption-enabled/step8.png)
9. Provide a unique "Cluster identifier (name)" to a new cluster and choose the "Master user password" and "Confirm password" of new cluster.![Step](/resources/aws/redshift/redshift-encryption-enabled/step9.png)
10. Under the "Launch your Amazon Redshift cluster - Advanced settings" select the "Database encryption" to "KMS" and select the "Master key" from dropdown menu. ![Step](/resources/aws/redshift/redshift-encryption-enabled/step10.png)
11. Click on the "Continue" button at the bottom of the configuration page. ![Step](/resources/aws/redshift/redshift-encryption-enabled/step11.png)
12. Review the new cluster configuration and click on the "Launch configuration" button at the bottom to launch a new cluster.![Step](/resources/aws/redshift/redshift-encryption-enabled/step12.png)
13. Once the new "Cluster Status" value changes to available and the "DB Health" status changes to healthy, the new cluster can used to load the existing data using Amazon Redshift Unload/Copy utility from unencrypted cluster to encrypted cluster.![Step](/resources/aws/redshift/redshift-encryption-enabled/step13.png)
14. Once the data migraton process is completed from unencrypted cluster to the new encrypted cluser delete the old unecncrypted cluster. </br>
15. Select the older unecncyrpted cluster and click on the "Cluster" dropdown menu at the top and click on the "Delete" option. ![Step](/resources/aws/redshift/redshift-encryption-enabled/step15.png)
16. On the "Delete Cluster" tab click on the "Delete" button to delete the unencrypted cluster.![Step](/resources/aws/redshift/redshift-encryption-enabled/step16.png)
