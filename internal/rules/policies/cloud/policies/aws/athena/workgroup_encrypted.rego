# METADATA
# title :"Workgroup Encrypted"
# description: "Ensures Athena workgroups are configured to encrypt all data at rest."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/athena/latest/ug/encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Athena
#   severity: LOW
#   short_code: workgroup-encrypted 
#   recommended_action: "Enable encryption at rest for all Athena workgroups."
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
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.athena, function(region, rcb){
#            var listWorkGroups = helpers.addSource(cache, source,
#                ['athena', 'listWorkGroups', region]);
#
#            if (!listWorkGroups) return rcb();
#
#            if (listWorkGroups.err || !listWorkGroups.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list Athena workgroups: ' + helpers.addError(listWorkGroups), region);
#                return rcb();
#            }
#
#            if (!listWorkGroups.data.length) {
#                helpers.addResult(results, 0, 'No Athena workgroups found', region);
#                return rcb();
#            }
#
#            // Loop through certificates
#            listWorkGroups.data.forEach(function(wg){
#                var getWorkGroup = helpers.addSource(cache, source,
#                    ['athena', 'getWorkGroup', region, wg.Name]);
#
#                // arn:aws:athena:region:account-id:workgroup/workgroup-name
#                var arn = 'arn:aws:athena:' + region + ':' + accountId + ':workgroup/' + wg.Name;
#
#                if (!getWorkGroup || getWorkGroup.err || !getWorkGroup.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe Athena workgroup: ' + helpers.addError(getWorkGroup), region, arn);
#                } else if (getWorkGroup.data.WorkGroup &&
#                           getWorkGroup.data.WorkGroup.Configuration &&
#                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration &&
#                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration &&
#                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption) {
#                    helpers.addResult(results, 0,
#                        'Athena workgroup is using ' + getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption + ' encryption', region, arn);
#                } else {
#                    // Check for empty primary workgroups
#                    if (wg.Name == 'primary' &&
#                        (!getWorkGroup.data.WorkGroup ||
#                         !getWorkGroup.data.WorkGroup.Configuration ||
#                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration ||
#                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.OutputLocation)) {
#                        helpers.addResult(results, 0, 'Athena primary workgroup does not have encryption enabled but is not in use.', region, arn);
#                    } else {
#                        helpers.addResult(results, 2, 'Athena workgroup is not using encryption', region, arn);
#                    }
#                }
#            });
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }