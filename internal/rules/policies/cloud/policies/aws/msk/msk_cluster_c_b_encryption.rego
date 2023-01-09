# METADATA
# title :"MSK Cluster Client Broker Encryption"
# description: "Ensure that only TLS encryption between the client and broker feature is enabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MSK
#   severity: LOW
#   short_code: msk-cluster-c-b-encryption 
#   recommended_action: "Enable only TLS encryption between the client and broker for all MSK clusters"
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
#                if (cluster.EncryptionInfo && 
#                    cluster.EncryptionInfo.EncryptionInTransit && 
#                    cluster.EncryptionInfo.EncryptionInTransit.ClientBroker &&
#                    cluster.EncryptionInfo.EncryptionInTransit.ClientBroker.toUpperCase() === 'TLS') {
#                    helpers.addResult(results, 0,
#                        'Encryption between the client and broker is only TLS encrypted', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Encryption between the client and broker is not only TLS encrypted', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }