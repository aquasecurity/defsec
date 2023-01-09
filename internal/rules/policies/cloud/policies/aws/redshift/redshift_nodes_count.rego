# METADATA
# title :"Redshift Nodes Count"
# description: "Ensures that each AWS region has not reached the limit set for the number of Redshift cluster nodes."
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
#   short_code: redshift-nodes-count 
#   recommended_action: "Remove Redshift clusters over defined limit"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var redshift_nodes_count = parseInt(settings.redshift_nodes_count || this.settings.redshift_nodes_count.default);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
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
#            var nodesCount = 0;
#            describeClusters.data.forEach(cluster => {
#                if (!cluster.ClusterIdentifier) return;
#
#                if (cluster.NumberOfNodes) {
#                    nodesCount = nodesCount + cluster.NumberOfNodes;
#                }
#            });
#
#            if (nodesCount <= redshift_nodes_count) {
#                helpers.addResult(results, 0,
#                    `Region contains "${nodesCount}" provisioned Redshift nodes of "${redshift_nodes_count}" limit`, region);
#            } else {
#                helpers.addResult(results, 2,
#                    `Region contains "${nodesCount}" provisioned Redshift nodes of "${redshift_nodes_count}" limit`, region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }