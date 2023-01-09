# METADATA
# title :"Container Insights Enabled"
# description: "Ensure that ECS clusters have CloudWatch Container Insights feature enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ECS
#   severity: LOW
#   short_code: ecs-container-insights-enabled 
#   recommended_action: "Enabled container insights feature for ECS clusters."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback){
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ecs, function(region, rcb){
#
#            var listClusters = helpers.addSource(cache, source, 
#                ['ecs','listClusters',region]);
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(results, 3, 
#                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (!listClusters.data.length) {
#                helpers.addResult(results, 0, 'No ECS clusters present', region);
#                return rcb();
#            }
#
#            for (var clusterARN of listClusters.data) {
#                var describeCluster = helpers.addSource(cache, source,
#                    ['ecs', 'describeCluster', region, clusterARN]);
#        
#                if (!describeCluster || describeCluster.err ||!describeCluster.data ||
#                    !describeCluster.data.clusters || !describeCluster.data.clusters.length) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe ECS cluster: ' +helpers.addError(describeCluster), region, clusterARN);
#                    continue;
#                }
#
#                const cluster = describeCluster.data.clusters[0];
#                let containerInsightsEnabled = (cluster.settings && cluster.settings.length) ? cluster.settings.find(item => item.name == 'containerInsights' && item.value == 'enabled') : false;
#
#                if (containerInsightsEnabled) {
#                    helpers.addResult(results, 0,
#                        'ECS cluster has container insights enabled', region, clusterARN);
#                } else {
#                    helpers.addResult(results, 2,
#                        'ECS cluster does not have container insights enabled', region, clusterARN);
#                }             
#            }
#            rcb();
#        },
#        function(){
#            callback(null, results, source);
#        });
#    }