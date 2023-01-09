# METADATA
# title :"WorkSpaces Desired Bundle Type"
# description: "Ensure that AWS WorkSpaces bundles are of desired types."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-bundles.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:WorkSpaces
#   severity: LOW
#   short_code: workspaces-desired-bundle-type 
#   recommended_action: "Ensure that WorkSpaces instances are using desired bundle types"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var workspace_desired_bundle_type = settings.workspace_desired_bundle_type || this.settings.workspace_desired_bundle_type.default;
#
#        if (!workspace_desired_bundle_type.length) return callback(null, results, source);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.workspaces, function(region, rcb){
#            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);
#
#            if (!listWorkspaces) {
#                return rcb();
#            }
#
#            if (listWorkspaces.err || !listWorkspaces.data) {
#                helpers.addResult(
#                    results, 3, 'Unable to query for WorkSpaces information: ' + helpers.addError(listWorkspaces), region);
#                return rcb();
#            }
#
#            if (!listWorkspaces.data.length) {
#                helpers.addResult(
#                    results, 0, 'No WorkSpaces instances found', region);
#                return rcb();
#            }
#
#            listWorkspaces.data.forEach(workspace => {
#                var resource = 'arn:' + awsOrGov + ':workspaces:' + region + ':' + accountId + ':workspace/' + workspace.WorkspaceId;
#
#                if (workspace.WorkspaceProperties && workspace.WorkspaceProperties.ComputeTypeName && workspace_desired_bundle_type.toUpperCase().includes(workspace.WorkspaceProperties.ComputeTypeName.toUpperCase())) {
#                    helpers.addResult(results, 0,
#                        'WorkSpaces instance is using the desired bundle type', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'WorkSpaces instance is not using the desired bundle type', region, resource);
#                }
#            });
#
#            return rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }