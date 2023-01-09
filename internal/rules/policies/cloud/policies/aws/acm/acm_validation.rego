# METADATA
# title :"ACM Certificate Validation"
# description: "ACM certificates should be configured to use DNS validation."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/blogs/security/easier-certificate-validation-using-dns-with-aws-certificate-manager/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ACM
#   severity: LOW
#   short_code: acm-validation 
#   recommended_action: "Configure ACM managed certificates to use DNS validation."
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
#
#            // Loop through certificates
#            listCertificates.data.forEach(function(cert){
#                var describeCertificate = helpers.addSource(cache, source,
#                    ['acm', 'describeCertificate', region, cert.CertificateArn]);
#
#                if (!describeCertificate || describeCertificate.err || !describeCertificate.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe ACM certificate: ' + helpers.addError(describeCertificate), region, cert.CertificateArn);
#                } else if (describeCertificate.data.Certificate &&
#                           describeCertificate.data.Certificate.Type &&
#                           describeCertificate.data.Certificate.Type !== 'AMAZON_ISSUED') {
#                    helpers.addResult(results, 0,
#                        'Non AWS-issued certificates do not support AWS DNS validation', region, cert.CertificateArn);
#                } else if (!describeCertificate.data.Certificate ||
#                           !describeCertificate.data.Certificate.DomainValidationOptions ||
#                           !describeCertificate.data.Certificate.DomainValidationOptions.length) {
#                    helpers.addResult(results, 2,
#                        'ACM certificate does not have DomainValidationOptions', region, cert.CertificateArn);
#                } else {
#                    describeCertificate.data.Certificate.DomainValidationOptions.forEach(function(domain) {
#                        if (!domain.ValidationStatus || domain.ValidationStatus != 'SUCCESS') {
#                            helpers.addResult(results, 2, domain.DomainName + ' has failed ' + (domain.ValidationMethod || '') + ' validation.', region, cert.CertificateArn);
#                        } else if (!domain.ValidationMethod || domain.ValidationMethod != 'DNS') {
#                            helpers.addResult(results, 1, domain.DomainName + ' is using ' + (domain.ValidationMethod || '') + ' validation.', region, cert.CertificateArn);
#                        } else {
#                            helpers.addResult(results, 0, domain.DomainName + ' is using ' + (domain.ValidationMethod || '') + ' validation.', region, cert.CertificateArn);
#                        }
#                    });
#                }
#            });
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }