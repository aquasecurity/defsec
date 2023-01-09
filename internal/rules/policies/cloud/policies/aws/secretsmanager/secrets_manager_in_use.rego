# METADATA
# title :"Secrets Manager In Use"
# description: "Ensure that Amazon Secrets Manager service is being used in your account to manage all the credentials."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/secretsmanager/latest/userguide/asm_access.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Secrets Manager
#   severity: LOW
#   short_code: secrets-manager-in-use 
#   recommended_action: "Use Secrets Manager service to store sensitive information in your AWS account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.secretsmanager, (region, rcb) => {
#            var listSecrets = helpers.addSource(cache, source, ['secretsmanager', 'listSecrets', region]);
#
#            if (!listSecrets) return rcb();
#
#            if (!listSecrets.data || listSecrets.err) {
#                helpers.addResult(results, 3, `Unable to query for Secrets Manager secrets: ${helpers.addError(listSecrets)}`, region);
#                return rcb();
#            }
#
#            if (!listSecrets.data.length) {
#                helpers.addResult(results, 2, `Secrets Manager is not enabled: ${helpers.addError(listSecrets)}`, region);
#                return rcb();
#            } else {
#                helpers.addResult(results, 0, 'Secrets Manager is enabled', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }