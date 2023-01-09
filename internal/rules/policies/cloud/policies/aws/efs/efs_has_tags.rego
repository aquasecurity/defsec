# METADATA
# title :"EFS Has Tags"
# description: "Ensure that AWS EFS file systems have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/efs/latest/ug/manage-fs-tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EFS
#   severity: LOW
#   short_code: efs-has-tags 
#   recommended_action: "Modify EFS file systems to add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.efs, function(region, rcb) {
#            var describeFileSystems = helpers.addSource(cache, source,
#                ['efs', 'describeFileSystems', region]);
#
#            if (!describeFileSystems) return rcb();
#
#            if (describeFileSystems.err || !describeFileSystems.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
#                return rcb();
#            }
#
#            if (!describeFileSystems.data.length){
#                helpers.addResult(results, 0, 'No EFS file systems present', region);
#                return rcb();
#            }
#
#            for (var efs of describeFileSystems.data) {
#                const { FileSystemArn, Tags} = efs;
#
#                if (!Tags.length){
#                    helpers.addResult(results, 2, 'EFS file system does not have tags associated', region, FileSystemArn);
#                } else {
#                    helpers.addResult(results, 0, 'EFS file system has tags', region, FileSystemArn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }