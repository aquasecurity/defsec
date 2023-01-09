# METADATA
# title :"ElastiCache Nodes Count"
# description: "Ensure that the number of ElastiCache cluster cache nodes has not reached the limit quota established by your organization."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: elasticache-nodes-count 
#   recommended_action: "Enable limit for ElastiCache cluster nodes count"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        
#        var config = {
#            elasticache_nodes_count_per_region: parseInt(settings.elasticache_nodes_count_per_region || this.settings.elasticache_nodes_count_per_region.default),
#            elasticache_nodes_count_global: parseInt(settings.elasticache_nodes_count_global || this.settings.elasticache_nodes_count_global.default)
#        };
#
#        var globalCount = 0;
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
#            var nodesCount = 0;
#            describeCacheClusters.data.forEach(cluster => {
#                if (!cluster.CacheClusterId) return;
#
#                if (cluster.NumCacheNodes) {
#                    nodesCount = nodesCount + cluster.NumCacheNodes;
#                    globalCount = globalCount + cluster.NumCacheNodes;
#                }
#            });
#
#            if (nodesCount <= config.elasticache_nodes_count_per_region) {
#                helpers.addResult(results, 0,
#                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_per_region}" limit`, region);
#            } else {
#                helpers.addResult(results, 2,
#                    `Region contains "${nodesCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_per_region}" limit`, region);
#            }
#
#            rcb();
#        }, function(){
#            if (globalCount <= config.elasticache_nodes_count_global) {
#                helpers.addResult(results, 0,
#                    `Region contains "${globalCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_global}" limit`, 'global');
#            } else {
#                helpers.addResult(results, 2,
#                    `Region contains "${globalCount}" provisioned ElastiCache nodes of "${config.elasticache_nodes_count_global}" limit`, 'global');
#            }
#
#            callback(null, results, source);
#        });
#    }