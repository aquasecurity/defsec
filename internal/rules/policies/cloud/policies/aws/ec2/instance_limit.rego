# METADATA
# title :"Instance Limit"
# description: "Determine if the number of EC2 instances is close to the AWS per-account limit"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: instance-limit 
#   recommended_action: "Contact AWS support to increase the number of instances available"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || this.settings.instance_limit_percentage_fail.default,
#            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || this.settings.instance_limit_percentage_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeAccountAttributes = helpers.addSource(cache, source,
#                ['ec2', 'describeAccountAttributes', region]);
#
#            if (!describeAccountAttributes) return rcb();
#
#            if (describeAccountAttributes.err || !describeAccountAttributes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for account limits: ' + helpers.addError(describeAccountAttributes), region);
#                return rcb();
#            }
#
#            var limits = {
#                'max-instances': 20
#            };
#
#            // Loop through response to assign custom limits
#            for (var i in describeAccountAttributes.data) {
#                if (limits[describeAccountAttributes.data[i].AttributeName]) {
#                    limits[describeAccountAttributes.data[i].AttributeName] = describeAccountAttributes.data[i].AttributeValues[0].AttributeValue;
#                }
#            }
#
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
#            var ec2Instances = 0;
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No instances found', region);
#                return rcb();
#            } else {
#                for (var instances in describeInstances.data){
#                    for (var instance in describeInstances.data[instances].Instances){
#                        if (!describeInstances.data[instances].Instances[instance].SpotInstanceRequestId){
#                            ec2Instances += 1;
#                        }
#                    }
#                }
#            }
#
#            var percentage = Math.ceil((ec2Instances / limits['max-instances'])*100);
#            var returnMsg = 'Account contains ' + ec2Instances + ' of ' + limits['max-instances'] + ' (' + percentage + '%) available instances';
#
#            if (percentage >= config.instance_limit_percentage_fail) {
#                helpers.addResult(results, 2, returnMsg, region, null, custom);
#            } else if (percentage >= config.instance_limit_percentage_warn) {
#                helpers.addResult(results, 1, returnMsg, region, null, custom);
#            } else {
#                helpers.addResult(results, 0, returnMsg, region, null, custom);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }