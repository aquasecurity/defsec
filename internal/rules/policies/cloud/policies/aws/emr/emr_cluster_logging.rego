# METADATA
# title :"EMR Cluster Logging"
# description: "Ensure AWS Elastic MapReduce (EMR) clusters capture detailed log data to Amazon S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EMR
#   severity: LOW
#   short_code: emr-cluster-logging 
#   recommended_action: "Modify EMR clusters to enable cluster logging"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.emr, function(region, rcb){
#            var listClusters = helpers.addSource(cache, source,
#                ['emr', 'listClusters', region]);
#            
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EMR clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length) {
#                helpers.addResult(results, 0, 'No EMR cluster found', region);
#                return rcb();
#            }
#
#            async.each(listClusters.data, function(cluster, ccb){
#                if (!cluster.Id) ccb();
#
#                var resource = cluster.ClusterArn;
#                
#                var describeCluster = helpers.addSource(cache, source,
#                    ['emr', 'describeCluster', region, cluster.Id]);
#                
#                if (!describeCluster || describeCluster.err || !describeCluster.data || !describeCluster.data.Cluster) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for EMR cluster', region, resource);
#                    return ccb();
#                }
#
#                if (describeCluster.data.Cluster.LogUri &&
#                    describeCluster.data.Cluster.LogUri !== '') {
#                    helpers.addResult(results, 0,
#                        `EMR cluster logging is enabled for "${cluster.Name}" cluster`, region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `EMR cluster logging is not enabled for "${cluster.Name}" cluster`, region, resource);
#                }
#
#                ccb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }