# METADATA
# title :"Redshift Unused Reserved Nodes"
# description: "Ensures that Amazon Redshift Reserved Nodes are being utilized."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/redshift/latest/mgmt/purchase-reserved-node-instance.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-unused-reserved-nodes 
#   recommended_action: "Provision new Redshift clusters matching the criteria of reserved nodes"
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
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            var describeReservedNodes = helpers.addSource(cache, source,
#                ['redshift', 'describeReservedNodes', region]);
#    
#            if (!describeReservedNodes) return rcb();
#
#            if (describeReservedNodes.err || !describeReservedNodes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Redshift reserved nodes: ' + helpers.addError(describeReservedNodes), region);
#                return rcb();
#            }
#
#            if (!describeReservedNodes.data.length) {
#                helpers.addResult(results, 0, 'No Redshift reserved nodes found', region);
#                return rcb();
#            }
#
#            if (!describeClusters || describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Redshift clusters: ' + helpers.addError(describeClusters), region);
#                return rcb();
#            }
#
#            var usedReservedNodes = [];
#            describeClusters.data.forEach(cluster => {
#                if (!cluster.ClusterIdentifier) return;
#
#                if (!usedReservedNodes.includes(cluster.NodeType)) {
#                    usedReservedNodes.push(cluster.NodeType);
#                }
#            });
#
#            describeReservedNodes.data.forEach(node => {
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:reserved-node:${node.ReservedNodeId}`;
#                if (usedReservedNodes.includes(node.NodeType)) {
#                    helpers.addResult(results, 0,
#                        `Redshift reserved node "${node.ReservedNodeId}" is being used`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Redshift reserved node "${node.ReservedNodeId}" is not being used`,
#                        region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }