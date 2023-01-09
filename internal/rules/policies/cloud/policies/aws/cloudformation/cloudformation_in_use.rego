# METADATA
# title :"AWS CloudFormation In Use"
# description: "Ensure that Amazon CloudFormation service is in use within your AWS account to automate your infrastructure management and deployment."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFormation
#   severity: LOW
#   short_code: cloudformation-in-use 
#   recommended_action: "Check if CloudFormation is in use or not by observing the stacks"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#       
#        async.each(regions.cloudformation, function(region, rcb){
#            var describeStacks = helpers.addSource(cache, source,
#                ['cloudformation', 'describeStacks', region]);
#
#            if (!describeStacks) return rcb();
#
#            if (describeStacks.err || !describeStacks.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query CloudFormation stacks: ${helpers.addError(describeStacks)}`, region);
#                return rcb();
#            }
#
#            if (describeStacks.data.length) {
#                helpers.addResult(results, 0,
#                    'CloudFormation service is being used',
#                    region); 
#            } else {
#                helpers.addResult(results, 2,
#                    'CloudFormation service is not being used',
#                    region);  
#            }
#           
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }