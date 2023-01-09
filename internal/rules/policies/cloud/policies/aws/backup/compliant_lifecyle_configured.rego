# METADATA
# title :"AWS Backup Compliant Lifecycle Configured"
# description: "Ensure that a compliant lifecycle configuration is enabled for your Amazon Backup plans in order to meet compliance requirements when it comes to security and cost optimization."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_Lifecycle.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Backup
#   severity: LOW
#   short_code: compliant-lifecyle-configured 
#   recommended_action: "Enable compliant lifecycle configuration for your Amazon Backup plans"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.backup, function(region, rcb) {
#            var listBackupPlans = helpers.addSource(cache, source,
#                ['backup', 'listBackupPlans', region]);
#
#            if (!listBackupPlans) return rcb();
#
#            if (listBackupPlans.err || !listBackupPlans.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list Backup plans: ' + helpers.addError(listBackupPlans), region);
#                return rcb();
#            }
#
#            if (!listBackupPlans.data.length) {
#                helpers.addResult(results, 0, 'No Backup plans found', region);
#                return rcb();
#            }
#
#            for (let plan of listBackupPlans.data) {
#                if (!plan.BackupPlanArn) continue;
#
#                var resource = plan.BackupPlanArn;
#                var getBackupPlan = helpers.addSource(cache, source,
#                    ['backup', 'getBackupPlan', region, plan.BackupPlanId]);
#
#                if (!getBackupPlan || getBackupPlan.err || !getBackupPlan.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get Backup plan description: ${helpers.addError(getBackupPlan)}`,
#                        region, resource);
#                    continue;
#                }
#
#                if (!getBackupPlan.data.BackupPlan ||
#                    !getBackupPlan.data.BackupPlan.Rules) {
#                    helpers.addResult(results, 2,
#                        'No lifecycle configuration rules found for Backup plan', region, resource);
#                    continue;
#                }
#                
#                let found = getBackupPlan.data.BackupPlan.Rules.find(rule => rule.Lifecycle && rule.Lifecycle.DeleteAfterDays && rule.Lifecycle.MoveToColdStorageAfterDays);
#                if (found) {
#                    helpers.addResult(results, 0,
#                        'Backup plan has lifecycle configuration enabled', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Backup plan does not have lifecycle configuration enabled', region, resource);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }