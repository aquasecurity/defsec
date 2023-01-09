# METADATA
# title :"MSK Cluster Public Access"
# description: "Ensure that public access feature within the cluster is disabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MSK
#   severity: LOW
#   short_code: msk-cluster-public-access 
#   recommended_action: "Check for public access feature within the cluster for all MSK clusters"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.kafka, function(region, rcb){
#            var listClusters = helpers.addSource(cache, source,
#                ['kafka', 'listClusters', region]);
#
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for MSK clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length) {
#                helpers.addResult(results, 0, 'No MSK clusters found', region);
#                return rcb();
#            }
#            
#            for (var cluster of listClusters.data) {
#                if (!cluster.ClusterArn) continue;
#
#                var resource = cluster.ClusterArn;
#
#                if (cluster.BrokerNodeGroupInfo &&
#                    cluster.BrokerNodeGroupInfo.ConnectivityInfo && 
#                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess && 
#                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type &&
#                    cluster.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type.toUpperCase() === 'DISABLED') {
#                    helpers.addResult(results, 0,
#                        'MSK cluster is not publicly accessible', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'MSK cluster is publicly accessible', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }