# METADATA
# title :"Redshift Parameter Group SSL Required"
# description: "Ensures AWS Redshift non-default parameter group associated with Redshift cluster require SSL connection."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-s-s-l-enabled 
#   recommended_action: "Update Redshift parameter groups to have require-ssl parameter set to true."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            var describeClusterParameterGroups = helpers.addSource(cache, source,
#                ['redshift', 'describeClusterParameterGroups', region]);
#
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0,
#                    'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            if (!describeClusterParameterGroups || describeClusterParameterGroups.err || !describeClusterParameterGroups.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Redshift cluster parameter groups: ${helpers.addError(describeClusterParameterGroups)}`, region);
#                return rcb();
#            }
#            
#            async.each(describeClusters.data, function(cluster, ccb){
#                if (!cluster.ClusterIdentifier) return ccb();
#
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#                var requireSsl = false;
#
#                for (var cg in cluster.ClusterParameterGroups) {
#                    var clusterParameterGroup = cluster.ClusterParameterGroups[cg];
#                    var groupName = clusterParameterGroup.ParameterGroupName;
#
#                    if (!groupName.startsWith('default.redshift')) {
#                        var describeClusterParameters = helpers.addSource(cache, source,
#                            ['redshift', 'describeClusterParameters', region, groupName]);
#    
#                        if (!describeClusterParameters ||
#                            describeClusterParameters.err ||
#                            !describeClusterParameters.data ||
#                            !describeClusterParameters.data.Parameters) {
#                            helpers.addResult(results, 3,
#                                `Unable to query parameter group "${groupName}": ${helpers.addError(describeClusterParameters)}`, 
#                                region, resource);
#                            return ccb();
#                        }
#    
#                        
#                        for (var p in describeClusterParameters.data.Parameters) {
#                            var param = describeClusterParameters.data.Parameters[p];
#    
#                            if (param.ParameterName && param.ParameterName === 'require_ssl' &&
#                                param.ParameterValue && param.ParameterValue === 'true') {
#                                requireSsl = true;
#                                break;
#                            }
#                        }
#                    }
#
#                    if (requireSsl) break;
#                }
#                
#                if (requireSsl) {
#                    helpers.addResult(results, 0,
#                        `Parameter group associated with Redshift cluster "${clusterIdentifier}" requires SSL connection`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Parameter group associated with Redshift cluster "${clusterIdentifier}" does not require SSL connection`,
#                        region, resource);
#                }
#
#                ccb();
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }