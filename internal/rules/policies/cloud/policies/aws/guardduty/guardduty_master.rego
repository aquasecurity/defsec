# METADATA
# title :"GuardDuty Master Account"
# description: "Ensures GuardDuty master account is correct"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html#guardduty_master
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:GuardDuty
#   severity: LOW
#   short_code: guardduty-master 
#   recommended_action: "Configure the member account to send GuardDuty findings to a known master account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var regions = helpers.regions(settings);
#
#        var guarddutyMasterAccount = settings.guardduty_master_account || this.settings.guardduty_master_account.default;
#
#        async.each(regions.guardduty, function(region, rcb) {
#            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
#            if (!listDetectors) return rcb();
#            if (listDetectors.err || !listDetectors.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list guardduty detectors: ' + helpers.addError(listDetectors), region);
#                return rcb();
#            } else if (listDetectors.data.length > 0) {
#                for (let detectorId of listDetectors.data) {
#                    var getMasterAccount = helpers.addSource(cache, source, ['guardduty', 'getMasterAccount', region, detectorId]);
#
#                    var arn = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
#                    if (!getMasterAccount || !getMasterAccount.data.Master) {
#                        helpers.addResult(results, 2, 'GuardDuty master account is not configured', region, arn);
#                    } else {
#                        if (getMasterAccount.data.Master.RelationshipStatus !== 'Enabled') {
#                            helpers.addResult(results, 2, 'GuardDuty master account not enabled', region, arn);
#                        } else {
#                            if (guarddutyMasterAccount === '') {
#                                helpers.addResult(results, 0, 'GuardDuty has master account configured', region, arn);
#                            } else if (getMasterAccount.data.Master.AccountId === guarddutyMasterAccount) {
#                                helpers.addResult(results, 0, `GuardDuty master account is account ${guarddutyMasterAccount}`, region, arn);
#                            } else {
#                                helpers.addResult(results, 2, `GuardDuty master account is not account ${guarddutyMasterAccount}`, region, arn);
#                            }
#                        }
#                    }
#                }
#            } else if (listDetectors.data.length === 0) {
#                helpers.addResult(results, 2, 'No GuardDuty detectors found', region, arn);
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }