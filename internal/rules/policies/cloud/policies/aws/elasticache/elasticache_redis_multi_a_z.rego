# METADATA
# title :"ElastiCache Redis Cluster Have Multi-AZ"
# description: "Ensure that your ElastiCache Redis Cache clusters are using a Multi-AZ deployment configuration to enhance High Availability."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html#AutoFailover.Enable
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: elasticache-redis-multi-a-z 
#   recommended_action: "Enable Redis Multi-AZ for ElastiCache clusters"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elasticache, function(region, rcb) {
#            var describeCacheClusters = helpers.addSource(cache, source,
#                ['elasticache', 'describeCacheClusters', region]);
#
#            if (!describeCacheClusters) return rcb();
#
#            if (describeCacheClusters.err || !describeCacheClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query elasticache clusters: ' + helpers.addError(describeCacheClusters), region);
#                return rcb();
#            }
#
#            if (!describeCacheClusters.data.length) {
#                helpers.addResult(results, 0, 'No elasticache clusters found', region);
#                return rcb();
#            }
#
#            for (let cluster of describeCacheClusters.data) {
#                if (!cluster.ARN) continue;
#
#                var resource = cluster.ARN;
#                var describeReplicationGroups = helpers.addSource(cache, source,
#                    ['elasticache', 'describeReplicationGroups', region, cluster.ReplicationGroupId]);
#
#                if (!describeReplicationGroups || describeReplicationGroups.err || !describeReplicationGroups.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get clusters description: ${helpers.addError(describeReplicationGroups)}`,
#                        region, resource);
#                } else {
#                    if (describeReplicationGroups.data.ReplicationGroups &&
#                        describeReplicationGroups.data.ReplicationGroups.some(group => group.MultiAZ && group.MultiAZ.toLowerCase() === 'enabled')) {
#                        helpers.addResult(results, 0,
#                            'Cluster has Multi-AZ feature enabled', region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Cluster does not have Multi-AZ feature enabled', region, resource);
#                    }
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }