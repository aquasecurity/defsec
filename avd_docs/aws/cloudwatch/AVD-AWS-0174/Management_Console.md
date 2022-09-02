1. Log in to the AWS Management Console at https://console.aws.amazon.com/.
2. Open the Amazon Cloudwatch console.
3. In the left navigation, click Logs.
4. Select the log group that you created for CloudTrail log events.
5. Choose Actions > Create Metric Filter.
6. On the Define Pattern screen, enter: `{ ($.eventSource = organizations.amazonaws.com) }`
7. Select Next.
8. Enter a filter name.
9. Enter a metric namespace.
10. Enter a metric name.
11. For Metric Value, type 1.
12. Select Next.
13. Select Create Metric Filter.
14. Create an Alarm:
15. On the Metric Filters tab of the same log group, check the box for the filter you just created and click Create Alarm.
16. On the Create Alarm page, provide the following values:
17. Under Statistic, select Sum.
18. Under Period, select 5 minutes.
19. Under Threshold type, select Static.
20. Under “Whenever <filter name> is…” select Greater/Equal.
21. Under “than…” enter 1.
22. Set Datapoints to alarm to 1 out of 1.
23. Select Next.
24. On the Configure Actions page, provide the following values:
25. Under Alarm state trigger, select In alarm.
26. Under Select an SNS topic, click Select an existing SNS topic.
27. Under Send a notification to… select the desired topic.
28. Select next.
29. Enter an alarm name and description.
30. Click Create Alarm.