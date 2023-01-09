# METADATA
# title :"Unused WorkSpaces"
# description: "Ensure that there are no unused AWS WorkSpaces instances available within your AWS account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/workspaces/pricing/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:WorkSpaces
#   severity: LOW
#   short_code: unused-workspaces 
#   recommended_action: "Identify and remove unused Workspaces instance"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#       
#        var awsOrGov = helpers.defaultPartition(settings);
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion , 'data']);
#
#        async.each(regions.workspaces, function(region, rcb){
#            var describeWorkspacesConnectionStatus = helpers.addSource(cache, source,
#                ['workspaces', 'describeWorkspacesConnectionStatus', region]);
#
#            if (!describeWorkspacesConnectionStatus) return rcb();
#
#            if (describeWorkspacesConnectionStatus.err || !describeWorkspacesConnectionStatus.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for WorkSpaces instance connection status: ' + helpers.addError(describeWorkspacesConnectionStatus), region);
#                return rcb();
#            }
#
#            if (!describeWorkspacesConnectionStatus.data.length) {   
#                helpers.addResult(results, 0, 'No WorkSpaces instance connection status found', region);
#                return rcb();
#            }
#            
#            describeWorkspacesConnectionStatus.data.forEach(workspace => {
#                if (!workspace.WorkspaceId) return;
#
#                let resource = `arn:${awsOrGov}:region:${region}:${accountId}:worskpace/${workspace.WorkspaceId}`;
#
#                if (!workspace.LastKnownUserConnectionTimestamp) {
#                    helpers.addResult(results, 2,
#                        'WorkSpace does not have any known user connection', region, resource);
#                } else if (workspace.LastKnownUserConnectionTimestamp &&
#                    (helpers.daysBetween(new Date(), workspace.LastKnownUserConnectionTimestamp)) > 30) {
#                    helpers.addResult(results, 2,
#                        `WorkSpace is not in use for last ${helpers.daysBetween(new Date(), workspace.LastKnownUserConnectionTimestamp)}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'WorkSpace is in use', region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }