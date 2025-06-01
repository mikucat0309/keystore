use android_hardware_security_keymint::aidl::android::hardware::security::keymint::Digest::Digest;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
};
use anyhow::Result;
use clap::Args;
use clap::builder::{PossibleValuesParser, TypedValueParser};

use crate::authorizations::AuthSetBuilder;
use crate::{common, enum_parser};

#[derive(Args, Clone, Debug)]
pub struct GenerateParams {
    /// key size
    #[arg(
        short = 'n',
        long = "size",
        value_name = "INT",
        default_value_t = 2048,
    )]
    key_size: i32,

    /// allowed key purpose
    #[arg(
        short = 'P',
        long,
        num_args = 1..,
        value_delimiter = ',',
        value_parser = enum_parser!([
            ("encrypt", KeyPurpose::ENCRYPT),
            ("decrypt", KeyPurpose::DECRYPT),
            ("sign", KeyPurpose::SIGN),
        ]),
        default_value = "encrypt,decrypt,sign",
    )]
    purpose: Vec<KeyPurpose>,

    /// allowed block mode
    #[arg(
        short = 'b',
        long = "block",
        num_args = 1..,
        value_delimiter = ',',
        value_parser = enum_parser!([
            ("ECB", BlockMode::ECB),
        ]),
        default_value = "ECB",
    )]
    block_mode: Vec<BlockMode>,

    /// allowed padding mode
    #[arg(
        short = 'p',
        long = "padding",
        num_args = 1..,
        value_delimiter = ',',
        value_parser = enum_parser!([
            ("NONE", PaddingMode::NONE),
            ("PKCS1", PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            ("OAEP", PaddingMode::RSA_OAEP),
        ]),
        default_value = "PKCS1",
    )]
    padding_mode: Vec<PaddingMode>,

    /// allowed digest
    #[arg(
        short = 'd',
        long,
        num_args = 1..,
        value_delimiter = ',',
        value_parser = enum_parser!([
            ("SHA1", Digest::SHA1),
            ("SHA224", Digest::SHA_2_224),
            ("SHA256", Digest::SHA_2_256),
            ("SHA384", Digest::SHA_2_384),
            ("SHA512", Digest::SHA_2_512),
        ]),
    )]
    digest: Vec<Digest>,
}

pub fn generate_with_alias(alias: &str, params: &GenerateParams) -> Result<KeyMetadata> {
    let key = &common::key_descriptor_from_alias(alias);
    generate(key, params)
}

pub fn generate(key: &KeyDescriptor, params: &GenerateParams) -> Result<KeyMetadata> {
    let mut key_params = AuthSetBuilder::new()
        .algorithm(Algorithm::RSA)
        .key_size(params.key_size)
        .rsa_public_exponent(65537);
    for x in &params.purpose {
        key_params = key_params.purpose(x.to_owned())
    }
    for x in &params.block_mode {
        key_params = key_params.block_mode(x.to_owned())
    }
    for x in &params.padding_mode {
        key_params = key_params.padding_mode(x.to_owned())
    }
    for x in &params.digest {
        key_params = key_params.digest(x.to_owned())
    }

    common::generate(key, &key_params)
}
