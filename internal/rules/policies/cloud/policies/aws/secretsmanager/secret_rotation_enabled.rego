# METADATA
# title :"Secrets Manager Secret Rotation Enabled"
# description: "Ensures AWS Secrets Manager is configured to automatically rotate the secret for a secured service or database."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Secrets Manager
#   severity: LOW
#   short_code: secret-rotation-enabled 
#   recommended_action: "Enable secret rotation for your secrets"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            secretsmanager_secret_rotation_interval: parseInt(settings.secretsmanager_secret_rotation_interval || this.settings.secretsmanager_secret_rotation_interval.default)
#        };
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
#                helpers.addResult(results, 0, 'No secrets found', region);
#                return rcb();
#            }
#
#            async.each(listSecrets.data, (secret, scb) => {
#                if (!secret.ARN) return scb();
#
#                var resource = secret.ARN;
#
#                var describeSecret = helpers.addSource(cache, source,
#                    ['secretsmanager', 'describeSecret', region, resource]);
#
#                if (!describeSecret || describeSecret.err || !describeSecret.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to query Secrets Manager secret: ${helpers.addError(describeSecret)}`, region, resource);
#                    return scb();
#                }
#
#                if (describeSecret.data.RotationEnabled &&
#                    describeSecret.data.RotationRules &&
#                    describeSecret.data.RotationRules.AutomaticallyAfterDays) {
#                    var rotationInterval = describeSecret.data.RotationRules.AutomaticallyAfterDays;
#                    
#                    if (rotationInterval >= config.secretsmanager_secret_rotation_interval) {
#                        helpers.addResult(results, 0,
#                            `Rotation is enabled for Secrets Manager secret and rotation interval is ${rotationInterval} days`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Rotation is enabled for Secrets Manager secret but set rotation interval ${rotationInterval} is less than desired interval of ${config.secretsmanager_secret_rotation_interval} days`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Rotation is not enabled for Secrets Manager secret', region, resource);
#                }
#
#                scb();
#            }, function(){
#                rcb();
#            });
#
#        }, function(){
#            callback(null, results, source);
#        });
#    }