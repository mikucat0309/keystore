use android_hardware_security_keymint::aidl::android::hardware::security::keymint::Digest::Digest;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
};
use anyhow::Result;
use clap::Args;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use x509_cert::der::Encode;
use x509_cert::name::RdnSequence;

use crate::common;

#[derive(Args, Clone, Debug)]
pub struct GenerateParams {
    // key purpose
    #[arg(
        long = "purpose",
        num_args = 1..,
        value_delimiter = ',',
        value_parser = PossibleValuesParser::new(["encrypt" ,"decrypt", "sign"])
            .map(|x| match x.as_str() {
              "encrypt" => KeyPurpose::ENCRYPT,
              "decrypt" => KeyPurpose::DECRYPT,
              "sign" => KeyPurpose::SIGN,
              _ => panic!("impossible"),
            }),
        default_value = "encrypt,decrypt,sign",
    )]
    purposes: Vec<KeyPurpose>,

    // block mode
    #[arg(
        long = "block",
        num_args = 1..,
        value_delimiter = ',',
        value_parser = PossibleValuesParser::new(["ECB"])
            .map(|x| match x.as_str() {
                "ECB" => BlockMode::ECB,
                _ => panic!("impossible"),
            }),
        default_value = "ECB",
    )]
    block_mode: Vec<BlockMode>,

    // padding mode
    #[arg(
        long = "padding",
        num_args = 1..,
        value_delimiter = ',',
        value_parser = PossibleValuesParser::new(["NONE", "PKCS1", "OAEP"])
            .map(|x| match x.as_str() {
                "NONE" => PaddingMode::NONE,
                "PKCS1" => PaddingMode::RSA_PKCS1_1_5_ENCRYPT,
                "OAEP" => PaddingMode::RSA_OAEP,
                _ => panic!("impossible"),
            }),
        default_value = "NONE,PKCS1,OAEP",
    )]
    padding_mode: Vec<PaddingMode>,

    // digest
    #[arg(
        long,
        num_args = 1..,
        value_delimiter = ',',
        value_parser = PossibleValuesParser::new(["SHA256", "SHA384", "SHA512"])
            .map(|x| match x.as_str() {
                "SHA256" => Digest::SHA_2_256,
                "SHA384" => Digest::SHA_2_384,
                "SHA512" => Digest::SHA_2_512,
                _ => panic!("impossible"),
            }),
        default_value = "SHA256,SHA384,SHA512",
    )]
    digest: Vec<Digest>,

    // key size
    #[arg(long = "size", value_name = "INT", default_value_t = 2048)]
    key_size: i32,

    // RSA public exponent
    #[arg(long = "exponent", value_name = "INT", default_value_t = 65537)]
    public_exponent: i64,

    // certificate serial number
    #[arg(long = "serial", value_name = "INT", default_value_t = 1)]
    cert_serial: u8,

    // certificate subject distinguished name
    #[arg(long = "subject", value_name = "STRING", default_value = "CN=Fake")]
    cert_subject: RdnSequence,
}

pub fn generate_with_alias(alias: &str, params: &GenerateParams) -> Result<KeyMetadata> {
    let key = &common::key_descriptor_from_alias(alias);
    generate(key, params)
}

pub fn generate(key: &KeyDescriptor, params: &GenerateParams) -> Result<KeyMetadata> {
    let key_params = &mut vec![
        KeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm::RSA),
        },
        KeyParameter {
            tag: Tag::KEY_SIZE,
            value: KeyParameterValue::Integer(params.key_size),
        },
        KeyParameter {
            tag: Tag::RSA_PUBLIC_EXPONENT,
            value: KeyParameterValue::LongInteger(params.public_exponent),
        },
        KeyParameter {
            tag: Tag::CERTIFICATE_SUBJECT,
            value: KeyParameterValue::Blob(params.cert_subject.to_der()?),
        },
        KeyParameter {
            tag: Tag::CERTIFICATE_SERIAL,
            value: KeyParameterValue::Blob(vec![params.cert_serial]),
        },
    ];
    key_params.append(
        &mut params
            .purposes
            .iter()
            .map(|x| KeyParameter {
                tag: Tag::PURPOSE,
                value: KeyParameterValue::KeyPurpose(x.to_owned()),
            })
            .collect(),
    );
    key_params.append(
        &mut params
            .block_mode
            .iter()
            .map(|x| KeyParameter {
                tag: Tag::BLOCK_MODE,
                value: KeyParameterValue::BlockMode(x.to_owned()),
            })
            .collect(),
    );
    key_params.append(
        &mut params
            .padding_mode
            .iter()
            .map(|x| KeyParameter {
                tag: Tag::PADDING,
                value: KeyParameterValue::PaddingMode(x.to_owned()),
            })
            .collect(),
    );
    key_params.append(
        &mut params
            .digest
            .iter()
            .map(|x| KeyParameter {
                tag: Tag::DIGEST,
                value: KeyParameterValue::Digest(x.to_owned()),
            })
            .collect(),
    );
    common::generate(key, key_params)
}
