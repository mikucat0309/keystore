use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use anyhow::Result;

use crate::common;

#[allow(deprecated)]
pub fn list() -> Result<Vec<KeyDescriptor>> {
    let ks2 = common::get_instance()?;
    let keys = ks2.listEntries(Domain::APP, -1)?;
    Ok(keys)
}
