use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, KeyPurpose::KeyPurpose,
};
use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use anyhow::Result;

use crate::authorizations::AuthSetBuilder;
use crate::common;

use super::CryptParams;

pub fn decrypt_with_alias(alias: &str, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let key = &common::key_descriptor_from_alias(alias);
    decrypt(key, params, input)
}

pub fn decrypt(key: &KeyDescriptor, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let mut key_params = AuthSetBuilder::new()
        .algorithm(Algorithm::RSA)
        .purpose(KeyPurpose::DECRYPT)
        .block_mode(params.block_mode.to_owned())
        .padding_mode(params.padding_mode.to_owned());
    if let Some(digest) = params.digest {
        key_params = key_params.digest(digest);
    }

    common::crypt(key, &key_params, input)
}
