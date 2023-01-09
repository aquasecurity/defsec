# METADATA
# title :"ElastiCache Cluster In VPC"
# description: "Ensure that your ElastiCache clusters are provisioned within the AWS VPC platform."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VPCs.EC.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: elasticache-cluster-in-vpc 
#   recommended_action: "Create ElastiCache clusters within VPC network"
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
#                if (cluster.CacheSubnetGroupName &&
#                    cluster.CacheSubnetGroupName.length) {
#                    helpers.addResult(results, 0,
#                        `ElastiCache cluster  "${cluster.CacheClusterId}" is in VPC`, region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `ElastiCache cluster  "${cluster.CacheClusterId}" is not in VPC`, region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }