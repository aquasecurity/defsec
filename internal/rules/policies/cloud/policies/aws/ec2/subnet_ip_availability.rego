# METADATA
# title :"Subnet IP Availability"
# description: "Determine if a subnet is at risk of running out of IP addresses"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: subnet-ip-availability 
#   recommended_action: "Add a new subnet with larger CIDR block and migrate resources."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            subnet_ip_availability_percentage_fail: settings.subnet_ip_availability_percentage_fail || this.settings.subnet_ip_availability_percentage_fail.default,
#            subnet_ip_availability_percentage_warn: settings.subnet_ip_availability_percentage_warn || this.settings.subnet_ip_availability_percentage_warn.default
#        };
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeSubnets = helpers.addSource(cache, source,
#                ['ec2', 'describeSubnets', region]);
#
#            if (!describeSubnets) return rcb();
#
#            if (describeSubnets.err || !describeSubnets.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for subnets: ' + helpers.addError(describeSubnets), region);
#                return rcb();
#            }
#
#            if (!describeSubnets.data.length) {
#                helpers.addResult(results, 0, 'No subnets found', region);
#                return rcb();
#            }
#
#            for (var i in describeSubnets.data){
#                if (describeSubnets.data[i] && describeSubnets.data[i].CidrBlock) {
#                    var subnetSize = helpers.cidrSize(describeSubnets.data[i].CidrBlock);
#                    var consumedIPs = subnetSize - describeSubnets.data[i].AvailableIpAddressCount;
#                    var percentageConsumed = Math.ceil((consumedIPs / subnetSize) * 100);
#                    var subnetArn = 'arn:aws:ec2:' + region + ':' + accountId + ':subnet/' + describeSubnets.data[i].SubnetId;
#
#                    var returnMsg = 'Subnet ' + describeSubnets.data[i].SubnetId
#                        + ' is using ' + consumedIPs + ' of '
#                        + subnetSize + ' (' + percentageConsumed + '%) available IPs.';
#
#                    if (percentageConsumed >= config.subnet_ip_availability_percentage_fail) {
#                        helpers.addResult(results, 2, returnMsg, region, subnetArn, custom);
#                    } else if (percentageConsumed >= config.subnet_ip_availability_percentage_warn) {
#                        helpers.addResult(results, 1, returnMsg, region, subnetArn, custom);
#                    } else {
#                        helpers.addResult(results, 0, returnMsg, region, subnetArn, custom);
#                    }
#                } else {
#                    helpers.addResult(results, 3, 'No CIDR data found', region);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }