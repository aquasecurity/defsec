# METADATA
# title :"MQ Desired Broker Instance Type"
# description: "Ensure that the Amazon MQ broker instances are created with desired instance types."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-broker-architecture.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MQ
#   severity: LOW
#   short_code: mq-desired-instance-type 
#   recommended_action: "Create MQ broker with desired instance types"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            mq_desired_instance_type: settings.mq_desired_instance_type || this.settings.mq_desired_instance_type.default
#        };
#        
#        if (!config.mq_desired_instance_type.length) return callback(null, results, source);
#
#        async.each(regions.mq, function(region, rcb){        
#            var listBrokers = helpers.addSource(cache, source,
#                ['mq', 'listBrokers', region]);
#
#            if (!listBrokers) return rcb();
#
#            if (listBrokers.err || !listBrokers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query MQ brokers: ' + helpers.addError(listBrokers), region);
#                return rcb();
#            }
#
#            if (!listBrokers.data.length) {
#                helpers.addResult(results, 0, 'No MQ brokers found', region);
#                return rcb();
#            }
#
#            for (var broker of listBrokers.data) {
#                if (!broker.BrokerArn) continue;
#
#                if (broker.HostInstanceType && broker.HostInstanceType.length &&
#                    config.mq_desired_instance_type.includes(broker.HostInstanceType)) {
#                    helpers.addResult(results, 0,
#                        `Broker has desired instance type: ${broker.HostInstanceType}`,
#                        region, broker.BrokerArn);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Broker does not have desired instance type: ${broker.HostInstanceType}`,
#                        region, broker.BrokerArn);
#                }
#            }
#
#            rcb();  
#        }, function(){
#            callback(null, results, source);
#        });
#    }