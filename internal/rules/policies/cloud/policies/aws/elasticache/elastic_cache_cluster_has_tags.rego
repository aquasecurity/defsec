# METADATA
# title :"ElastiCache Cluster Has Tags"
# description: "Ensure that ElastiCache clusters have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Tagging-Resources.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: elastic-cache-cluster-has-tags 
#   recommended_action: "Modify ElastiCache cluster and add tags."
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
#            const ARNList = [];
#            for (var cluster of describeCacheClusters.data) {
#                ARNList.push(cluster.ARN);
#            }
#            helpers.checkTags(cache, 'ElastiCache cluster', ARNList, region, results);
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }