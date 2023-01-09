# METADATA
# title :"Instance IAM Role"
# description: "Ensures EC2 instances are using an IAM role instead of hard-coded AWS credentials"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: instance-iam-role 
#   recommended_action: "Attach an IAM role to the EC2 instance"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            instance_iam_role_threshold: settings.instance_iam_role_threshold || this.settings.instance_iam_role_threshold.default
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
#                    if (!instance.IamInstanceProfile ||
#                        !instance.IamInstanceProfile.Arn) {
#                        found += 1;
#                        helpers.addResult(results, 2,
#                            'Instance does not use an IAM role', region,
#                            'arn:aws:ec2:' + region + ':' + accountId + ':instance/' +
#                            instance.InstanceId, custom);
#                    }
#                }
#            }
#
#            // Too many results to print individually
#            if (found > config.instance_iam_role_threshold) {
#                results = [];
#
#                helpers.addResult(results, 2,
#                    'Over ' + config.instance_iam_role_threshold + ' EC2 instances do not use an IAM role', region, null, custom);
#            }
#
#            if (!found) {
#                helpers.addResult(results, 0,
#                    'All ' + describeInstances.data.length + ' instances are using IAM roles', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }