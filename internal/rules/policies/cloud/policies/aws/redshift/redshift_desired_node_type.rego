# METADATA
# title :"Redshift Desired Node Type"
# description: "Ensures that Amazon Redshift cluster nodes are of given types."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-desired-node-type 
#   recommended_action: "Take snapshot of the Amazon Redshift cluster and launch a new cluster of the desired node type using the snapshot."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var redshift_cluster_node_type = settings.redshift_cluster_node_type || this.settings.redshift_cluster_node_type.default;
#
#        if (!redshift_cluster_node_type.length) return callback();
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            describeClusters.data.forEach(cluster => {
#                if (!cluster.ClusterIdentifier) return;
#
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#
#                if (cluster.NodeType && cluster.NodeType === redshift_cluster_node_type) {
#                    helpers.addResult(results, 0,
#                        'Redshift cluster is using the desired node type', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Redshift cluster is not using the desired node type', region, resource);
#                }
#            });
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }