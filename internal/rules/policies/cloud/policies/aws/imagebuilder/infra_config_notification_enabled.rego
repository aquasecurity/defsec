# METADATA
# title :"Infrastructure Configuration Notification Enabled"
# description: "Ensure that Image Builder infrastructure configurations have SNS notifications enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-infra-config.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Image Builder
#   severity: LOW
#   short_code: infra-config-notification-enabled 
#   recommended_action: "Enable SNS notification in EC2 Image Builder infrastructure configurations to get notified of any changes in the service."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.imagebuilder, function(region, rcb){        
#            var listInfrastructureConfigurations = helpers.addSource(cache, source,
#                ['imagebuilder', 'listInfrastructureConfigurations', region]);
#
#            if (!listInfrastructureConfigurations) return rcb();
#
#            if (listInfrastructureConfigurations.err || !listInfrastructureConfigurations.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for infrastructure configuration summary List: ${helpers.addError(listInfrastructureConfigurations)}`, region);
#                return rcb();
#            }
#
#            if (!listInfrastructureConfigurations.data.length) {
#                helpers.addResult(results, 0, 'No list infrastructure configuration found', region);
#                return rcb();
#            }
#
#            for (let recipe of listInfrastructureConfigurations.data) {
#                if (!recipe.arn) continue;
#
#                let resource = recipe.arn;
#
#                var getInfrastructureConfiguration = helpers.addSource(cache, source,
#                    ['imagebuilder', 'getInfrastructureConfiguration', region, recipe.arn]);
#
#                if (!getInfrastructureConfiguration || getInfrastructureConfiguration.err || !getInfrastructureConfiguration.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get infrastructure configuration description: ${helpers.addError(getInfrastructureConfiguration)}`,
#                        region, resource);
#                    continue;
#                } 
#               
#                if (getInfrastructureConfiguration.data.infrastructureConfiguration && 
#                    getInfrastructureConfiguration.data.infrastructureConfiguration.snsTopicArn) {
#                    helpers.addResult(results, 0,
#                        'Infrastructure configuration has SNS notifications enabled',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Infrastructure configuration does not have SNS notifications enabled',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }