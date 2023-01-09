# METADATA
# title :"EKS Cluster Has Tags"
# description: "Ensure that AWS EKS Clusters have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EKS
#   severity: LOW
#   short_code: eks-cluster-has-tags 
#   recommended_action: "Modify EKS Cluster and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.eks, function(region, rcb) {
#            var listClusters = helpers.addSource(cache, source,
#                ['eks', 'listClusters', region]);
#
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length) {
#                helpers.addResult(results, 0, 'No EKS clusters present', region);
#                return rcb();
#            }
#
#            const ARNList = [];
#            for (var clusterName of listClusters.data) {
#                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;
#                ARNList.push(arn);
#            }
#            
#            helpers.checkTags(cache,'EKS cluster', ARNList, region, results);
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }