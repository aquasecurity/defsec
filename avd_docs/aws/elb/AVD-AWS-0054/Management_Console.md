1. Log into the AWS Management Console.
2. Select the "Services" option and search for EC2. ![Step](/resources/aws/elb/elb-https-only/step2.png)
3. In the "EC2 Dashboard" scroll down and look for "Load Balancers" and click on "Load Balancers" to get into "Load Balancers" dashboard.![Step](/resources/aws/elb/elb-https-only/step3.png)
4. Select the "Load Balancer" which needs to be verified. ![Step](/resources/aws/elb/elb-https-only/step4.png)
5. Select the "Listeners" tab from the bottom panel and scroll down to the "Load Balancer Protocol" column. Check for "HTTP" under "Instance Protocol". ![Step](/resources/aws/elb/elb-https-only/step5.png)
6. On the "Listeners" tab scroll down and click on the "Edit" button to remove non-HTTPS listeners.![Step](/resources/aws/elb/elb-https-only/step6.png)
7. On "Edit listers" tab remove non-HTTPS listeners by clicking on cross icon at the extreme right and click on the "Save" button to make the necessary changes. ![Step](/resources/aws/elb/elb-https-only/step7.png)
8. ELBs are now configured to only accept the connection on HTTPS ports.