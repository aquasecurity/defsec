# METADATA
# title :"EC2 has Tags"
# description: "Ensure that AWS EC2 Instances have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ec2-has-tags 
#   recommended_action: "Modify EC2 instances and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeInstances = helpers.addSource(cache, source, ['ec2', 'describeInstances', region]);
#
#            if (!describeInstances) return rcb();
#
#            if (describeInstances.err || !describeInstances.data) {
#                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
#                return rcb();
#            }
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No EC2 instances found', region);
#                return rcb();
#            }
#
#            for (var instances of describeInstances.data){
#                const { OwnerId } = instances;
#
#                for (var instance of instances.Instances) {
#                    const { Tags, InstanceId } = instance;
#                    const arn = `arn:aws:ec2:${region}:${OwnerId}:instance/${InstanceId}`;
#                    if (!Tags || !Tags.length){
#                        helpers.addResult(results, 2, 'EC2 Instance does not have tags associated', region, arn);
#                    } else {
#                        helpers.addResult(results, 0, 'EC2 Instance has tags associated', region, arn);
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }