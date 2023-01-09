# METADATA
# title :"S3 Bucket Encryption"
# description: "Ensures object encryption is enabled on S3 buckets"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-encryption 
#   recommended_action: "Enable CMK KMS-based encryption for all S3 buckets."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            s3_encryption_require_cmk: settings.s3_encryption_require_cmk || this.settings.s3_encryption_require_cmk.default,
#            s3_encryption_allow_pattern: settings.s3_encryption_allow_pattern || this.settings.s3_encryption_allow_pattern.default,
#            s3_encryption_kms_alias: settings.s3_encryption_kms_alias || this.settings.s3_encryption_kms_alias.default,
#            s3_encryption_allow_cloudfront: settings.s3_encryption_allow_cloudfront || this.settings.s3_encryption_allow_cloudfront.default,
#            s3_allow_unencrypted_static_websites: settings.s3_allow_unencrypted_static_websites || this.settings.s3_allow_unencrypted_static_websites.default,
#            whitelist_appconfig_s3_buckets: settings.whitelist_appconfig_s3_buckets || this.settings.whitelist_appconfig_s3_buckets.default
#        };
#
#        config.s3_encryption_require_cmk = (config.s3_encryption_require_cmk == 'true');
#        config.s3_encryption_allow_cloudfront = (config.s3_encryption_allow_cloudfront == 'true');
#        config.s3_allow_unencrypted_static_websites = (config.s3_allow_unencrypted_static_websites == 'true');
#        config.whitelist_appconfig_s3_buckets = (config.whitelist_appconfig_s3_buckets == 'true');
#
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var defaultRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);
#
#        var cloudfrontOrigins = [];
#        var aliasKeyIds = [];
#        var defaultKeyIds = [];
#        var appConfigBuckets = [];
#        var defaultKeyDesc = 'Default master key that protects my S3 objects';
#
#        async.series([
#            // Lookup the default master key for S3 if required
#            function(cb) {
#                if (!config.s3_encryption_require_cmk) return cb();
#                async.each(regions.kms, function(region, rcb) {
#                    // List the KMS Keys
#                    var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);
#
#                    if (!listKeys) return rcb();
#
#                    if (listKeys.err || !listKeys.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for KMS: ' + helpers.addError(listKeys), region);
#                        return rcb();
#                    }
#
#                    if (!listKeys.data.length) return rcb();
#
#                    async.each(listKeys.data, function(key, kcb){
#                        // Describe the KMS keys
#                        var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);
#
#                        if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
#                            var keyToAdd = describeKey.data.KeyMetadata;
#
#                            if (keyToAdd.KeyManager && keyToAdd.KeyManager == 'AWS' && keyToAdd.Description &&
#                                keyToAdd.Description.indexOf(defaultKeyDesc) === 0) {
#                                defaultKeyIds.push(keyToAdd.Arn);
#                            }
#                        }
#                        
#                        kcb();
#                    }, function(){
#                        rcb();
#                    });
#                }, function(){
#                    cb();
#                });
#            },
#            // Lookup the key aliases if required
#            function(cb) {
#                if (!config.s3_encryption_kms_alias) return cb();
#                var configAliasIds = config.s3_encryption_kms_alias.split(',');
#
#                async.each(regions.kms, function(region, rcb) {
#                    var listAliases = helpers.addSource(cache, source,
#                        ['kms', 'listAliases', region]);
#
#                    var aliasIds = [];
#
#                    if (!listAliases || listAliases.err ||
#                        !listAliases.data) {
#                        return rcb();
#                    }
#
#                    if (!listAliases.data.length) {
#                        return rcb();
#                    }
#
#                    listAliases.data.forEach(function(alias){
#                        if (configAliasIds.indexOf(alias.AliasName) > -1) {
#                            aliasIds.push(alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId));
#                        }
#                    });
#
#                    if (aliasIds.length) aliasKeyIds = aliasKeyIds.concat(aliasIds);
#
#                    rcb();
#                }, function(){
#                    cb();
#                });
#            },
#            // Find buckets serving as CloudFront origins
#            function(cb){
#                if (!config.s3_encryption_allow_cloudfront) return cb();
#                var region = helpers.defaultRegion(settings);
#
#                var listDistributions = helpers.addSource(cache, source,
#                    ['cloudfront', 'listDistributions', region]);
#
#                if (!listDistributions) return cb();
#
#                if (listDistributions.err || !listDistributions.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
#                    return cb();
#                }
#
#                listDistributions.data.forEach(function(distribution){
#                    if (distribution.Origins &&
#                        distribution.Origins.Items &&
#                        distribution.Origins.Items.length) {
#                        distribution.Origins.Items.forEach(function(item){
#                            if (item.S3OriginConfig &&
#                                item.DomainName && item.DomainName.indexOf('.s3.') > -1) {
#                                // Below regex replaces the AWS-provided DNS for S3 buckets
#                                cloudfrontOrigins.push(item.DomainName.replace(/\.s3\..*amazonaws\.com/g, ''));
#                            }
#                        });
#                    }
#                });
#
#                cb();
#            },
#            function(cb){
#                if (!config.whitelist_appconfig_s3_buckets) return cb(); 
#
#                async.each(regions.appconfig, function(region, rcb) {
#                    var listApplications = helpers.addSource(cache, source,
#                        ['appconfig', 'listApplications', region]);
#
#                    if (!listApplications) return rcb();
#
#                    if (listApplications.err || !listApplications.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for AppConfig applications: ' + helpers.addError(listApplications), region);
#                        return rcb();
#                    }
#
#                    if (listApplications.data.length) {
#                        listApplications.data.forEach(function(application){
#                            if (!application.Id) return;
#                            let resource = `arn:${awsOrGov}:appconfig:${region}:${accountId}:application/${application.Id}`;
#
#                            var listConfigurationProfiles = helpers.addSource(cache, source,
#                                ['appconfig', 'listConfigurationProfiles', region, application.Id]);
#            
#                            if (!listConfigurationProfiles || listConfigurationProfiles.err ||
#                                !listConfigurationProfiles.data || !listConfigurationProfiles.data.Items) {
#                                helpers.addResult(results, 3,
#                                    `Unable to get configuration profiles description: ${helpers.addError(listConfigurationProfiles)}`,
#                                    region, resource); 
#                                return;
#                            }
#
#                            if (listConfigurationProfiles.data.Items.length) {
#                                for (let config of listConfigurationProfiles.data.Items){
#                                    if (config.LocationUri && config.LocationUri.startsWith('s3://')) {
#                                        let bucketName = config.LocationUri.split('/')[2];
#                                        if (!appConfigBuckets.includes(bucketName)) appConfigBuckets.push(bucketName);
#                                    }
#                                }
#                            }
#                        });
#                    }
#
#                    rcb();
#                }, function(){
#                    cb();
#                });
#            },
#            // Check the S3 buckets for encryption
#            function(cb) {
#                var region = helpers.defaultRegion(settings);
#
#                var listBuckets = helpers.addSource(cache, source,
#                    ['s3', 'listBuckets', region]);
#
#                if (!listBuckets) return cb();
#
#                if (listBuckets.err || !listBuckets.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
#                    return cb();
#                }
#
#                if (!listBuckets.data.length) {
#                    helpers.addResult(results, 0, 'No S3 buckets to check');
#                    return cb();
#                }
#
#                var allowRegex = (config.s3_encryption_allow_pattern &&
#                    config.s3_encryption_allow_pattern.length) ? new RegExp(config.s3_encryption_allow_pattern) : false;
#
#                listBuckets.data.forEach(function(bucket){
#                    let bucketResource = 'arn:aws:s3:::' + bucket.Name;
#                    var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
#                    if (config.whitelist_appconfig_s3_buckets && appConfigBuckets.includes(bucket.Name)) {
#                        helpers.addResult(results, 0,
#                            'Bucket is a source to AppConfig configuration profile',
#                            bucketLocation, bucketResource);
#                        return;
#                    }
#
#                    if (allowRegex && allowRegex.test(bucket.Name)) {
#                        helpers.addResult(results, 0,
#                            'Bucket: ' + bucket.Name + ' is whitelisted via custom setting.',
#                            bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
#                    } else {
#                        if (config.s3_allow_unencrypted_static_websites) {
#                            var getBucketWebsite = helpers.addSource(cache, source, ['s3', 'getBucketWebsite', region, bucket.Name]);
#                            if (getBucketWebsite && getBucketWebsite.err && getBucketWebsite.err.code && getBucketWebsite.err.code === 'NoSuchWebsiteConfiguration') {
#                                // do nothing
#                            } else if (!getBucketWebsite || getBucketWebsite.err || !getBucketWebsite.data) {
#                                helpers.addResult(results, 3, `Error querying for bucket website: ${bucket.Name}: ${helpers.addError(getBucketWebsite)}`, 'global', bucketResource);
#                                return;
#                            } else {
#                                helpers.addResult(results, 0,
#                                    'Bucket has static website hosting enabled', 'global', bucketResource, custom);
#                                return;
#                            }
#                        }
#
#                        var getBucketEncryption = helpers.addSource(cache, source,
#                            ['s3', 'getBucketEncryption', region, bucket.Name]);
#
#                        if (getBucketEncryption && getBucketEncryption.err &&
#                            getBucketEncryption.err.code && getBucketEncryption.err.code == 'ServerSideEncryptionConfigurationNotFoundError') {
#                            helpers.addResult(results, 2,
#                                'Bucket: ' + bucket.Name + ' has encryption disabled',
#                                bucketLocation, bucketResource);
#                        } else if (!getBucketEncryption || getBucketEncryption.err || !getBucketEncryption.data) {
#                            helpers.addResult(results, 3,
#                                'Error querying bucket encryption for: ' + bucket.Name +
#                                ': ' + helpers.addError(getBucketEncryption),
#                                bucketLocation, bucketResource);
#                        } else if (getBucketEncryption.data.ServerSideEncryptionConfiguration &&
#                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules &&
#                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0] &&
#                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault &&
#                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm) {
#                            var algo = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm;
#                            var keyArn = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID;
#
#                            if (config.s3_encryption_require_cmk &&
#                                (algo == 'AES256' || (algo == 'aws:kms' && defaultKeyIds.indexOf(keyArn) > -1))) {
#                                if (config.s3_encryption_allow_cloudfront &&
#                                    cloudfrontOrigins.indexOf(bucket.Name) > -1) {
#                                    helpers.addResult(results, 0,
#                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled without a CMK but is a CloudFront origin',
#                                        bucketLocation, bucketResource, custom);
#                                } else {
#                                    helpers.addResult(results, 2,
#                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled but is not using a CMK',
#                                        bucketLocation, bucketResource, custom);
#                                }
#                            } else {
#                                if (config.s3_encryption_kms_alias) {
#                                    if (config.s3_encryption_allow_cloudfront &&
#                                        cloudfrontOrigins.indexOf(bucket.Name) > -1) {
#                                        helpers.addResult(results, 0,
#                                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled but is a CloudFront origin',
#                                            bucketLocation, bucketResource, custom);
#                                    } else if (!aliasKeyIds.length) {
#                                        helpers.addResult(results, 2,
#                                            'Bucket: ' + bucket.Name + ' has encryption enabled but matching KMS key alias ' + config.s3_encryption_kms_alias + ' could not be found in the account',
#                                            bucketLocation, bucketResource, custom);
#                                    } else if (algo == 'aws:kms' && aliasKeyIds.indexOf(keyArn) > -1) {
#                                        helpers.addResult(results, 0,
#                                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled using required KMS key: ' + keyArn,
#                                            bucketLocation, bucketResource, custom);
#                                    } else {
#                                        var msg;
#                                        if (algo !== 'aws:kms') {
#                                            msg = 'Bucket: ' + bucket.Name + ' encryption (' + algo + ') is not configured to use required KMS key';
#                                        } else {
#                                            msg = 'Bucket: ' + bucket.Name + ' encryption (' + algo + ' with key: ' + keyArn + ') is not configured to use required KMS key';
#                                        }
#
#                                        helpers.addResult(results, 2, msg,bucketLocation, bucketResource, custom);
#                                    }
#                                } else {
#                                    helpers.addResult(results, 0,
#                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled',
#                                        bucketLocation, bucketResource, custom);
#                                }
#                            }
#                        } else {
#                            helpers.addResult(results, 2,
#                                'Bucket: ' + bucket.Name + ' has encryption disabled',
#                                bucketLocation, bucketResource);
#                        }
#                    }
#                });
#
#                cb();
#            }
#        ], function(){
#            callback(null, results, source);
#        });
#    }