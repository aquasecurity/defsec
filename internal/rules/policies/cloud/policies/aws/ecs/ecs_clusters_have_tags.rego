# METADATA
# title :"ECS Cluster Has Tags"
# description: "Ensure that AWS ECS Clusters have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ECS
#   severity: LOW
#   short_code: ecs-clusters-have-tags 
#   recommended_action: "Modify ECS Cluster and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ecs, function(region, rcb) {
#            var listClusters = helpers.addSource(cache, source,
#                ['ecs', 'listClusters', region]);
#
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length){
#                helpers.addResult(results, 0, 'No ECS clusters present', region);
#                return rcb();
#            }
#
#            helpers.checkTags(cache,'ECS clsuters', listClusters.data, region, results);
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }