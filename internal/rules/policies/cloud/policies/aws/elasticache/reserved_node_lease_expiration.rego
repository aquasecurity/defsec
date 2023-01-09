# METADATA
# title :"ElastiCache Reserved Cache Node Lease Expiration"
# description: "Ensure that your AWS ElastiCache Reserved Cache Nodes are renewed before expiration in order to get a significant discount."
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
#   short_code: reserved-node-lease-expiration 
#   recommended_action: "Enable ElastiCache reserved cache nodes expiration days alert"
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
#                    'Unable to query for ElastiCache Reserved Cache Node: ' + helpers.addError(describeReservedCacheNodes), region);
#                return rcb();
#            }
#
#            if (!describeReservedCacheNodes.data.length) {
#                helpers.addResult(results, 0, 'No ElastiCache reserved cache nodes found', region);
#                return rcb();
#            }
#
#            for (var cluster of describeReservedCacheNodes.data) {
#                if (!cluster.ReservationARN) continue;
#
#                var resource = cluster.ReservationARN;
#
#                let start = cluster.StartTime;
#                let duration = cluster.Duration;
#
#                if (duration == 1 || duration == 3){
#                    duration = duration * 31536000;
#                }
#                
#                let expiry = Math.floor(new Date(start)) + (duration * 1000);
#                let expirationDays = Math.round((new Date(expiry).getTime() - new Date().getTime())/(24*60*60*1000));
#
#                if (expirationDays >= 30) {
#                    helpers.addResult(results, 0,
#                        'ElastiCache reserved cache node lease expires in ' + expirationDays + ' days', region, resource);
#                } else if (expirationDays > 0 ) {
#                    helpers.addResult(results, 2,
#                        'ElastiCache reserved cache node lease expires in ' + expirationDays + ' days', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'ElastiCache reserved cache node lease has expired', region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }