use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Digest::Digest, PaddingMode::PaddingMode,
};
use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use anyhow::{Result, anyhow};
use digest::Digest as _;
use md5::Md5;
use rand::rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PaddingScheme;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::common;

use super::CryptParams;

enum PaddingSchemeWrapper {
    Pkcs1v15Enc(Pkcs1v15Encrypt),
    Oaep(Oaep),
}

impl PaddingScheme for PaddingSchemeWrapper {
    fn encrypt<Rng: rand::TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            PaddingSchemeWrapper::Pkcs1v15Enc(p) => p.encrypt(rng, pub_key, msg),
            PaddingSchemeWrapper::Oaep(p) => p.encrypt(rng, pub_key, msg),
        }
    }

    fn decrypt<Rng: rand::TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &rsa::RsaPrivateKey,
        ciphertext: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            PaddingSchemeWrapper::Pkcs1v15Enc(p) => p.decrypt(rng, priv_key, ciphertext),
            PaddingSchemeWrapper::Oaep(p) => p.decrypt(rng, priv_key, ciphertext),
        }
    }
}

fn oaep_digest_from_ks(digest: Digest) -> Result<Box<dyn digest::DynDigest + Send + Sync>> {
    match digest {
        Digest::NONE => Err(anyhow!("OAEP digest must not be none")),
        Digest::MD5 => Ok(Box::new(Md5::new())),
        Digest::SHA1 => Ok(Box::new(Sha1::new())),
        Digest::SHA_2_224 => Ok(Box::new(Sha224::new())),
        Digest::SHA_2_256 => Ok(Box::new(Sha256::new())),
        Digest::SHA_2_384 => Ok(Box::new(Sha384::new())),
        Digest::SHA_2_512 => Ok(Box::new(Sha512::new())),
        _ => panic!("impossible"),
    }
}

fn oaep_from_digest(digest: Option<Digest>, mgf_digest: Option<Digest>) -> Result<Oaep> {
    let digest = digest.unwrap_or(Digest::NONE);
    let mgf_digest = mgf_digest.unwrap_or(Digest::SHA1);
    Ok(Oaep {
        digest: oaep_digest_from_ks(digest)?,
        mgf_digest: oaep_digest_from_ks(mgf_digest)?,
        label: None,
    })
}

fn padding_from_ks(
    padding: PaddingMode,
    digest: Option<Digest>,
    mgf_digest: Option<Digest>,
) -> Result<PaddingSchemeWrapper> {
    match padding {
        PaddingMode::RSA_PKCS1_1_5_ENCRYPT => {
            Ok(PaddingSchemeWrapper::Pkcs1v15Enc(Pkcs1v15Encrypt))
        }
        PaddingMode::RSA_OAEP => Ok(PaddingSchemeWrapper::Oaep(oaep_from_digest(
            digest, mgf_digest,
        )?)),
        other => Err(anyhow!("Unsupported padding mode: {other:?}.")),
    }
}

pub fn encrypt_with_alias(alias: &str, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let key = &common::key_descriptor_from_alias(alias);
    encrypt(key, params, input)
}

pub fn encrypt(key: &KeyDescriptor, params: &CryptParams, input: &[u8]) -> Result<Vec<u8>> {
    let ks2 = common::get_instance()?;
    let entry = ks2.getKeyEntry(key)?;
    let cert_der = entry
        .metadata
        .certificate
        .ok_or(anyhow!("Failed to get certificate."))?;
    let cert = Certificate::from_der(&cert_der)?;
    let pub_key_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der)?;

    let mut rng = rng();
    let padding = padding_from_ks(params.padding_mode, params.digest, None)?;
    let output = pub_key.encrypt(&mut rng, padding, input)?;
    Ok(output)
}
