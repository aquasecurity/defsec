**To create a metric filter and alarm**

1.  Open the CloudWatch console at [https://console.aws.amazon.com/cloudwatch/](https://console.aws.amazon.com/cloudwatch/)
    
1.   In the navigation pane, choose **Log groups**.
    
1.   Select the check box for the CloudWatch Logs log group that is associated with the CloudTrail trail that you created.
    
1.   From **Actions**, choose **Create Metric Filter**.
    
1.   Under **Define pattern**, do the following:
    
        a.  Copy the following pattern and then paste it into the **Filter Pattern** field.
        
         {($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}
        
        b.  Choose **Next**.
        
2.   Under **Assign metric**, do the following:
    
        a.  In **Filter name**, enter a name for your metric filter.
        
        b.  For **Metric namespace**, enter `LogMetrics`.
        
        If you use the same namespace for all of your CIS log metric filters, then all CIS Benchmark metrics are grouped together.
        
        c.  For **Metric name**, enter a name for the metric. Remember the name of the metric. You will need to select the metric when you create the alarm.
        
        d.  For **Metric value**, enter `1`.
        
        e.  Choose **Next**.
        
3.   Under **Review and create**, verify the information that you provided for the new metric filter. Then choose **Create metric filter**.
    
4.   Choose the **Metric filters** tab, then choose the metric filter that you just created.
    
     To choose the metric filter, select the check box at the upper right.
    
5.   Choose **Create Alarm**.
    
6.   Under **Specify metric and conditions**, do the following:
    
        a.  Under **Metric**, for **Statistic**, choose **Average**. For more information about the available statistics, see [Statistics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Statistic) in the _Amazon CloudWatch User Guide_.
        
        b.  Under **Conditions**, for **Threshold**, choose **Static**.
        
        c.  For **Define the alarm condition**, choose **Greater/Equal**.
        
        d.  For **Define the threshold value**, enter `1`.
        
        e.  Choose **Next**.
        
7.   Under **Configure actions**, do the following:
    
        a.  Under **Alarm state trigger**, choose **In alarm**.
        
        b.  Under **Select an SNS topic**, choose **Select an existing SNS topic**.
        
        c.  For **Send a notification to**, enter the name of the SNS topic that you created in the previous procedure.
        
        d.  Choose **Next**.
        
8.   Under **Add name and description**, enter a **Name** and **Description** for the alarm. For example, `CIS-3.8-S3BucketPolicyChanges`. Then choose **Next**.
    
9.   Under **Preview and create**, review the alarm configuration. Then choose **Create alarm**.