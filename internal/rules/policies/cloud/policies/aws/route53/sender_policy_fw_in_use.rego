# METADATA
# title :"Sender Policy Framework In Use"
# description: "Ensure that Sender Policy Framework (SPF) is used to stop spammers from spoofing your AWS Route 53 domain."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/rrsets-working-with.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Route53
#   severity: LOW
#   short_code: sender-policy-fw-in-use 
#   recommended_action: "Updated the domain records to have SPF."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#        var listHostedZones = helpers.addSource(cache, source,
#            ['route53', 'listHostedZones', region]);
#
#        if (!listHostedZones) return callback(null, results, source);
#        
#        if (listHostedZones.err || !listHostedZones.data) {
#            helpers.addResult(results, 3,
#                `Unable to query for hosted zones: ${helpers.addError(listHostedZones)}`,
#                region);
#            return callback(null, results, source);
#        }
#
#        
#        if (!listHostedZones.data.length) {
#            helpers.addResult(results, 0, 'No Route53 Hosted Zones found', region);
#            return callback(null, results, source);
#        }
#
#        async.each(listHostedZones.data, function(zone, cb){
#            if (!zone.Id) return cb();
#
#            var resource = `arn:aws:route53:::${zone.Id}`;
#
#            var listResourceRecordSets = helpers.addSource(cache, source,
#                ['route53', 'listResourceRecordSets', region, zone.Id]);
#
#            if (!listResourceRecordSets || listResourceRecordSets.err || !listResourceRecordSets.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for resource record sets: ${helpers.addError(listResourceRecordSets)}`,
#                    region, resource);
#                return cb();
#            }
#
#            if (!listResourceRecordSets.data.ResourceRecordSets || !listResourceRecordSets.data.ResourceRecordSets.length) {
#                helpers.addResult(results, 0,
#                    'No resource record sets found',
#                    region, resource);
#                return cb();
#            }
#
#            let enabled = listResourceRecordSets.data.ResourceRecordSets.find(recordSet =>
#                recordSet.Type && recordSet.Type.toUpperCase() == 'TXT' &&
#                recordSet.ResourceRecords.find(record => record.Value && record.Value.toLowerCase().includes('v=spf1')));
#
#            if (!enabled) {
#                helpers.addResult(results, 2,
#                    'Hosted Zone has does not have SPF enabled',
#                    region, resource);
#            } else {
#                helpers.addResult(results, 0,
#                    'Hosted Zone has SPF enabled',
#                    region, resource);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }