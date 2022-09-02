1. Get an MFA device such as one of the following. You can enable only one MFA device per AWS account root user or IAM user.

    - A virtual MFA device, which is a software app that is compliant with RFC 6238, a standards-based TOTP (time-based one-time password) algorithm. You can install the app on a phone or other device. For a list of a few supported apps that you can use as virtual MFA devices, see Multi-Factor Authentication
    - A FIDO security key with an AWS supported configuration, such as one of the FIDO2 devices discussed on the Multi-Factor Authentication page. 
    - A hardware-based MFA device, such as one of the AWS supported hardware token devices discussed on the Multi-Factor Authentication page.

2. Enable the MFA device. For information about enabling each type of MFA device, see the following pages:

    - Virtual MFA device: See [Enabling a virtual multi-factor authentication (MFA) device (console)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html)
    - FIDO security key: See [Enabling a FIDO security key (console)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_fido.html)
    - Hardware MFA device: See [Enabling a hardware MFA device (console)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html)
