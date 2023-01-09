# METADATA
# title :"ACM Certificate Has Tags"
# description: "Ensure that ACM Certificates have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/acm/latest/userguide/tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ACM
#   severity: LOW
#   short_code: acm-certificate-has-tags 
#   recommended_action: "Modify ACM certificate and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.acm, function(region, rcb){
#            var listCertificates = helpers.addSource(cache, source,
#                ['acm', 'listCertificates', region]);
#
#            if (!listCertificates) return rcb();
#
#            if (listCertificates.err || !listCertificates.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list ACM certificates: ' + helpers.addError(listCertificates), region);
#                return rcb();
#            }
#
#            if (!listCertificates.data.length) {
#                helpers.addResult(results, 0, 'No ACM certificates found', region);
#                return rcb();
#            }
#            const ARNList= [];
#            for (var cert of listCertificates.data){
#                if (!cert.CertificateArn) continue;
#                
#                ARNList.push(cert.CertificateArn);
#            }
#            helpers.checkTags(cache, 'ACM certificate', ARNList, region, results);
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }