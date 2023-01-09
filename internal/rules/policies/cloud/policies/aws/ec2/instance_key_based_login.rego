# METADATA
# title :"EC2 Instance Key Based Login"
# description: "Ensures EC2 instances have associated keys for password-less SSH login"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: instance-key-based-login 
#   recommended_action: "Ensure each EC2 instance has an associated SSH key and disable password login."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            instance_keypair_threshold: parseInt(settings.instance_keypair_threshold || this.settings.instance_keypair_threshold.default)
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeInstances = helpers.addSource(cache, source,
#                ['ec2', 'describeInstances', region]);
#
#            if (!describeInstances) return rcb();
#
#            if (describeInstances.err || !describeInstances.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
#                return rcb();
#            }
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No instances found', region);
#                return rcb();
#            }
#
#            var found = 0;
#
#            for (var i in describeInstances.data) {
#                var accountId = describeInstances.data[i].OwnerId;
#
#                for (var j in describeInstances.data[i].Instances) {
#                    var instance = describeInstances.data[i].Instances[j];
#
#                    if (!instance.KeyName) {
#                        found += 1;
#                        helpers.addResult(results, 2,
#                            'Instance does not have associated keys for password-less SSH login', region,
#                            'arn:aws:ec2:' + region + ':' + accountId + ':instance/' +
#                            instance.InstanceId, custom);
#                    }
#                }
#            }
#
#            // Too many results to print individually
#            if (found > config.instance_keypair_threshold) {
#                results = [];
#
#                helpers.addResult(results, 2,
#                    'Over ' + config.instance_keypair_threshold + ' EC2 instances do not have associated keys for password-less SSH login', region, null, custom);
#            }
#
#            if (!found) {
#                helpers.addResult(results, 0,
#                    'All ' + describeInstances.data.length + ' instances have associated keys for password-less SSH login', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }