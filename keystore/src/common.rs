use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata,
};
use anyhow::{Context, Result, anyhow};
use binder::Strong;
use rand::{TryRngCore, rng};

#[macro_export]
macro_rules! enum_parser {
    ([$(($key:expr, $value:expr)),* $(,)?]) => {
        PossibleValuesParser::new([$($key),*]).map(|x| match x.as_str() {
            $(
                $key => $value,
            )*
            _ => panic!("impossible"),
        })
    };
}

pub fn get_instance() -> Result<Strong<dyn IKeystoreService>> {
    let ks2_service_name = "android.system.keystore2.IKeystoreService/default";
    let ks2 = binder::check_interface::<dyn IKeystoreService>(ks2_service_name)
        .context("failed to bind service")?;
    Ok(ks2)
}

pub fn key_descriptor_from_alias(alias: &str) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(alias.to_owned()),
        blob: None,
    }
}

fn find_key_size(params: &[KeyParameter]) -> Result<usize> {
    let value = params
        .iter()
        .find(|&x| x.tag == Tag::KEY_SIZE)
        .map(|x| x.value.to_owned())
        .ok_or(anyhow!("Failed to find key size"))?;
    match value {
        KeyParameterValue::Integer(key_size) => Ok(key_size as usize),
        _ => Err(anyhow!("Failed to find key size")),
    }
}

fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut rng = rng();
    let mut buf = vec![0; length];
    rng.try_fill_bytes(&mut buf)?;
    Ok(buf)
}

pub fn generate(key: &KeyDescriptor, params: &[KeyParameter]) -> Result<KeyMetadata> {
    let key_size = find_key_size(params)?;
    let entropy = random_bytes(key_size.div_ceil(8))?;
    let ks2 = get_instance()?;
    let sec_level = ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)?;
    let metadata = sec_level.generateKey(key, None, params, 0, &entropy)?;
    Ok(metadata)
}

pub fn crypt(key: &KeyDescriptor, params: &[KeyParameter], input: &[u8]) -> Result<Vec<u8>> {
    let ks2 = get_instance()?;
    let entry = ks2.getKeyEntry(key)?;
    let level = entry
        .iSecurityLevel
        .ok_or(anyhow!("iSecurityLevel is None"))?;
    let op = level.createOperation(&entry.metadata.key, params, false)?;
    let iop = op.iOperation.ok_or(anyhow!("iOperation is None"))?;
    let output = iop
        .finish(Some(input), None)?
        .ok_or(anyhow!("output is None"))?;
    Ok(output)
}
