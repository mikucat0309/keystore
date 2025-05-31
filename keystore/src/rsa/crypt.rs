use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use anyhow::{anyhow, Result};
use clap::Args;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use rand::rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PaddingScheme;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use crate::common;

#[derive(Args, Clone, Debug)]
pub struct CryptParams {
    // block mode
    #[arg(
    long = "block",
    default_value = "ECB",
    value_parser = PossibleValuesParser::new(["ECB"])
        .map(|x| match x.as_str() {
            "ECB" => BlockMode::ECB,
            _ => panic!("impossible"),
        }),
    )]
    block_mode: BlockMode,

    // padding mode
    #[arg(
        long = "padding",
        default_value = "PKCS1",
        value_parser = PossibleValuesParser::new(["NONE", "PKCS1", "OAEP"])
            .map(|x| match x.as_str() {
                "NONE" => PaddingMode::NONE,
                "PKCS1" => PaddingMode::RSA_PKCS1_1_5_ENCRYPT,
                "OAEP" => PaddingMode::RSA_OAEP,
                _ => panic!("impossible"),
        }),
    )]
    padding_mode: PaddingMode,
}

fn padding_scheme_from_padding_mode(p: PaddingMode) -> impl PaddingScheme {
    match p {
        PaddingMode::RSA_PKCS1_1_5_ENCRYPT => Pkcs1v15Encrypt{},
        _ => panic!("unsupported"),
    }
}

pub fn encrypt_with_alias(
    alias: &str,
    params: &CryptParams,
    input: &[u8],
) -> Result<Vec<u8>> {
    let key = &common::key_descriptor_from_alias(alias);
    encrypt(key, params, input)
}

pub fn encrypt(key: &KeyDescriptor, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let ks2 = common::get_instance()?;

    let entry = ks2.getKeyEntry(key)?;
    let cert_der = entry.metadata.certificate.ok_or(anyhow!("Failed to get certificate."))?;
    let cert = Certificate::from_der(&cert_der)?;
    let pub_key_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der)?;

    let mut rng = rng();
    let padding = padding_scheme_from_padding_mode(params.padding_mode);
    let output = padding.encrypt(&mut rng, &pub_key, input)?;
    Ok(output)
}

pub fn decrypt_with_alias(
    alias: &str,
    params: &CryptParams,
    input: &[u8],
) -> Result<Vec<u8>> {
    let key = &common::key_descriptor_from_alias(alias);
    decrypt(key, params, input)
}

pub fn decrypt(key: &KeyDescriptor, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let key_params = &[
        KeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm::RSA),
        },
        KeyParameter {
            tag: Tag::PURPOSE,
            value: KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
        },
        KeyParameter {
            tag: Tag::BLOCK_MODE,
            value: KeyParameterValue::BlockMode(params.block_mode.to_owned()),
        },
        KeyParameter {
            tag: Tag::PADDING,
            value: KeyParameterValue::PaddingMode(params.padding_mode.to_owned()),
        },
    ];
    common::crypt(key, key_params, input)
}
