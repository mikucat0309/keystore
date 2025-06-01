use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use anyhow::Result;

use crate::common::{self, key_descriptor_from_alias};

pub fn delete_with_alias(alias: &str) -> Result<()> {
    let key = &key_descriptor_from_alias(alias);
    delete(key)
}

pub fn delete(key: &KeyDescriptor) -> Result<()> {
    let ks2 = common::get_instance()?;
    ks2.deleteKey(key)?;
    Ok(())
}
