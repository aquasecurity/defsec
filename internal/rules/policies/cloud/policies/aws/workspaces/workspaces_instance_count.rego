# METADATA
# title :"WorkSpaces Instance Count"
# description: "Ensure that the number of Amazon WorkSpaces provisioned in your AWS account has not reached set limit."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-limits.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:WorkSpaces
#   severity: LOW
#   short_code: workspaces-instance-count 
#   recommended_action: "Ensure that number of WorkSpaces created within your AWS account is within set limit"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var workspace_instance_limit = parseInt(settings.workspace_instance_limit || this.settings.workspace_instance_limit.default);
#        var instanceCount = 0;
#
#        async.each(regions.workspaces, function(region, rcb){
#            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);
#
#            if (!listWorkspaces) {
#                return rcb();
#            }
#
#            if (!listWorkspaces || listWorkspaces.err || !listWorkspaces.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list Workspaces: ' + helpers.addError(listWorkspaces), region);
#                return rcb();
#            }
#            
#            if (!listWorkspaces.data.length) {
#                helpers.addResult(results, 0,
#                    'No WorkSpaces instances found', region);
#                return rcb();
#            }
#
#            instanceCount += listWorkspaces.data.length;
#
#            rcb();
#        }, function(){
#            if (instanceCount > workspace_instance_limit){
#                helpers.addResult(results, 2, `WorkSpaces Instance count is ${instanceCount} of ${workspace_instance_limit} desired threshold`, 'global');
#            } else {
#                helpers.addResult(results, 0, `WorkSpaces Instance count is ${instanceCount} of ${workspace_instance_limit} desired threshold`, 'global');
#            }
#
#            callback(null, results, source);
#        });
#    }