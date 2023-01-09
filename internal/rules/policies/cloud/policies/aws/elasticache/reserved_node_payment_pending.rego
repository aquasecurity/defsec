# METADATA
# title :"ElastiCache Reserved Cache Node Payment Pending"
# description: "Ensure that payments for ElastiCache Reserved Cache Nodes available within your AWS account has been processed completely. "
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/elasticache/reserved-cache-nodes/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: reserved-node-payment-pending 
#   recommended_action: "Identify any pending payments for ElastiCache reserved cache nodes"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elasticache, function(region, rcb){
#            var describeReservedCacheNodes = helpers.addSource(cache, source,
#                ['elasticache', 'describeReservedCacheNodes', region]);
#
#            if (!describeReservedCacheNodes) return rcb();
#
#            if (describeReservedCacheNodes.err || !describeReservedCacheNodes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for ElastiCache reserved cache node: ' + helpers.addError(describeReservedCacheNodes), region);
#                return rcb();
#            }
#
#            if (!describeReservedCacheNodes.data.length) {
#                helpers.addResult(results, 0, 'No ElastiCache reserved cache node found', region);
#                return rcb();
#            }
#            
#            for (var cluster of describeReservedCacheNodes.data) {
#                if (!cluster.ReservationARN) continue;
#
#                var resource = cluster.ReservationARN;
#
#                if (cluster.State === 'payment-pending') {
#                    helpers.addResult(results, 2,
#                        'ElastiCache reserved cache node have pending payment', region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'ElastiCache reserved cache node does not have pending payment', region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }