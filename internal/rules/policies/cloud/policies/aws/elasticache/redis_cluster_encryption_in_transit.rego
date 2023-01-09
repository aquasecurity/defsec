# METADATA
# title :"ElastiCache Redis Cluster Encryption In-Transit"
# description: "Ensure that your AWS ElastiCache Redis clusters have encryption in-transit enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: redis-cluster-encryption-in-transit 
#   recommended_action: "Enable in-transit encryption for ElastiCache clusters"
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
#            var describeCacheClusters = helpers.addSource(cache, source,
#                ['elasticache', 'describeCacheClusters', region]);
#
#            if (!describeCacheClusters) return rcb();
#
#            if (describeCacheClusters.err || !describeCacheClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for ElastiCache clusters: ' + helpers.addError(describeCacheClusters), region);
#                return rcb();
#            }
#
#            if (!describeCacheClusters.data.length) {
#                helpers.addResult(results, 0, 'No ElastiCache clusters found', region);
#                return rcb();
#            }
#            
#            for (var cluster of describeCacheClusters.data) {
#                if (!cluster.ARN) continue;
#
#                var resource = cluster.ARN;
#
#                if (cluster.Engine !== 'redis'){
#                    helpers.addResult(results, 0, `Encryption is not supported for ${cluster.Engine}`, region, resource);
#                    continue ;
#                }
#
#                if (cluster.TransitEncryptionEnabled) {
#                    helpers.addResult(results, 0,
#                        'Cluster has in-transit encryption enabled', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Cluster does not have in-transit encryption enabled', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }