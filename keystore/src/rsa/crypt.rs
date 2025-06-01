use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    BlockMode::BlockMode, Digest::Digest, PaddingMode::PaddingMode,
};
use clap::Args;
use clap::builder::{PossibleValuesParser, TypedValueParser};

use crate::enum_parser;

#[derive(Args, Clone, Debug)]
pub struct CryptParams {
    /// block mode
    #[arg(
        short = 'b',
        long = "block",
        value_parser = enum_parser!([
            ("ECB", BlockMode::ECB),
        ]),
        default_value = "ECB",
    )]
    pub block_mode: BlockMode,

    /// padding mode
    #[arg(
        short = 'p',
        long = "padding",
        value_parser = enum_parser!([
            ("NONE", PaddingMode::NONE),
            ("PKCS1", PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
            ("OAEP", PaddingMode::RSA_OAEP),
        ]),
        default_value = "PKCS1",
    )]
    pub padding_mode: PaddingMode,

    /// OAEP digest
    #[arg(
        short = 'd',
        long,
        value_parser = enum_parser!([
            ("SHA1", Digest::SHA1),
            ("SHA256", Digest::SHA_2_256),
            ("SHA384", Digest::SHA_2_384),
            ("SHA512", Digest::SHA_2_512),
        ]),
    )]
    pub digest: Option<Digest>,
}
