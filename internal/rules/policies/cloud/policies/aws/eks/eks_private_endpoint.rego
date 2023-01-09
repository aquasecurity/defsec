# METADATA
# title :"EKS Private Endpoint"
# description: "Ensures the private endpoint setting is enabled for EKS clusters"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EKS
#   severity: LOW
#   short_code: eks-private-endpoint 
#   recommended_action: "Enable the private endpoint setting for all EKS clusters."
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
#                helpers.addResult(
#                    results, 3,
#                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (listClusters.data.length === 0){
#                helpers.addResult(results, 0, 'No EKS clusters present', region);
#                return rcb();
#            }
#
#            for (var c in listClusters.data) {
#                var clusterName = listClusters.data[c];
#                var describeCluster = helpers.addSource(cache, source,
#                    ['eks', 'describeCluster', region, clusterName]);
#
#                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;
#
#                if (!describeCluster || describeCluster.err || !describeCluster.data) {
#                    helpers.addResult(
#                        results, 3,
#                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
#                        region, arn);
#                    continue;
#                }
#
#                if (describeCluster.data.cluster &&
#                    describeCluster.data.cluster.resourcesVpcConfig &&
#                    describeCluster.data.cluster.resourcesVpcConfig.endpointPrivateAccess) {
#                    helpers.addResult(results, 0, 'EKS cluster has private endpoint enabled', region, arn);
#                } else {
#                    helpers.addResult(results, 2, 'EKS cluster does not have private endpoint enabled', region, arn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }