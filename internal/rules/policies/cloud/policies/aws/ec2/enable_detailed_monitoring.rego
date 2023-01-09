# METADATA
# title :"Instance Detailed Monitoring"
# description: "Ensure that EC2 instances have detailed monitoring feature enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: enable-detailed-monitoring 
#   recommended_action: "Modify EC2 instance to enable detailed monitoring."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        const results = [];
#        const source = {};
#        const regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb) {
#            const describeInstances = helpers.addSource(
#                cache, source, ['ec2', 'describeInstances', region]);
#
#            if (!describeInstances) return rcb();
#
#            if (describeInstances.err || !describeInstances.data) {
#                helpers.addResult(results, 3, `Unable to query for instances:
#                   ${helpers.addError(describeInstances)}`, region);
#                return rcb();
#            }
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No EC2 instances found', region);
#                return rcb();
#            }
#
#            for (const reservation of describeInstances.data) {
#                const accountId = reservation.OwnerId;
#                for (const instance of reservation.Instances) {
#                    const arn = 'arn:aws:ec2:' + region + ':' + accountId + ':instance/' + instance.InstanceId;
#
#                    if (instance.Monitoring && instance.Monitoring.State && instance.Monitoring.State.toLowerCase() === 'enabled') {
#                        helpers.addResult(results, 0,
#                            'Instance has enabled detailed monitoring', region, arn);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Instance does not have enabled detailed monitoring', region, arn);
#                    }
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }