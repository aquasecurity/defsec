# METADATA
# title :"Root Hardware MFA"
# description: "Ensures the root account is using a hardware MFA device"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: root-hardware-mfa 
#   recommended_action: "Enable a hardware MFA device for the root account and disable any virtual devices"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var getAccountSummary = helpers.addSource(cache, source,
#            ['iam', 'getAccountSummary', region]);
#
#        if (!getAccountSummary || !getAccountSummary.data ||
#            !getAccountSummary.data.AccountMFAEnabled) {
#            helpers.addResult(results, 2,
#                'Root account is not using an MFA device');
#            return callback(null, results, source);
#        }
#
#        var listVirtualMFADevices = helpers.addSource(cache, source,
#            ['iam', 'listVirtualMFADevices', region]);
#
#        if (!listVirtualMFADevices ||
#            listVirtualMFADevices.err ||
#            !listVirtualMFADevices.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for MFA devices: ' + helpers.addError(listVirtualMFADevices));
#            return callback(null, results, source);
#        }
#
#        var arn;
#
#        for (var r in listVirtualMFADevices.data) {
#            var obj = listVirtualMFADevices.data[r];
#
#            if (obj.SerialNumber && obj.SerialNumber.indexOf(':mfa/root-account-mfa-device') > -1) {
#                arn = obj.SerialNumber;
#                break;
#            }
#        }
#
#        if (arn) {
#            helpers.addResult(results, 2,
#                'A virtual MFA device was found for the root account', 'global', arn);
#        } else {
#            helpers.addResult(results, 0, 'Root account is using a hardware MFA device');
#        }
#
#        callback(null, results, source);
#    }