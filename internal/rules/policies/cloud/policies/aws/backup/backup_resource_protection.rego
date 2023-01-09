# METADATA
# title :"Backup Resource Protection"
# description: "Ensure that protected resource types feature is enabled and configured for Amazon Backup service within."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Backup
#   severity: LOW
#   short_code: backup-resource-protection 
#   recommended_action: "Enable protected resource type feature in order to meet compliance requirements."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            backup_resource_type:(settings.backup_resource_type || this.settings.backup_resource_type.default)
#        };
#
#        config.backup_resource_type = config.backup_resource_type.replace(/\s/g, '');
#
#        if (!config.backup_resource_type.length) return callback(null, results, source);
#
#        config.backup_resource_type = config.backup_resource_type.toLowerCase().split(',');
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.backup, function(region, rcb){
#            var describeRegionSettings = helpers.addSource(cache, source, 
#                ['backup', 'describeRegionSettings', region]);
#             
#            if (!describeRegionSettings || describeRegionSettings.err ||
#                !describeRegionSettings.data) {
#                helpers.addResult(results, 3, `Unable to query for Backup resource type opt in preference: ${helpers.addError(describeRegionSettings)}`, region);
#                return rcb();
#            }
#
#            if (!describeRegionSettings.data) {
#                helpers.addResult(results, 0, 'No Backup region settings found', region);
#                return rcb();
#            }
#
#            let loweredResourceTypes = Object.keys(describeRegionSettings.data).reduce((acc, key) => {
#                acc[key.toLowerCase().replace(/\s/g, '')] = describeRegionSettings.data[key];
#                return acc;
#            }, {});
#   
#        
#            let missingResourceTypes = [];
#            config.backup_resource_type.forEach(element => {
#                if (!loweredResourceTypes[element]) {
#                    missingResourceTypes.push(element);
#                }
#            });
#
#            if (!missingResourceTypes.length) {
#                helpers.addResult(results, 0,
#                    'All desired resource types are protected by Backup service', region);
#            } else {
#                helpers.addResult(results, 2,
#                    'These desired resource types are not protected by Backup service: ' + missingResourceTypes.join(', '), region);
#            } 
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }