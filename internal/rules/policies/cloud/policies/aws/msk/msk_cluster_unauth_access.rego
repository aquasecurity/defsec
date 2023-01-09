# METADATA
# title :"MSK Cluster Unauthenticated Access"
# description: "Ensure that unauthenticated access feature is disabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MSK
#   severity: LOW
#   short_code: msk-cluster-unauth-access 
#   recommended_action: "Ensure that MSK clusters does not have unauthenticated access enabled."
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
#                if (cluster.ClientAuthentication && 
#                    cluster.ClientAuthentication.Unauthenticated && 
#                    cluster.ClientAuthentication.Unauthenticated.Enabled) {
#                    helpers.addResult(results, 2,
#                        'Cluster has unauthenticated access enabled', region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Cluster does not have unauthenticated access enabled', region, resource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }