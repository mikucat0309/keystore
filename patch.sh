#!/usr/bin/env bash
set -e

sed -i '/rustc-cfg/s/android_ndk/android_vndk/' aosp/frameworks/native/libs/binder/rust/build.rs

if [[ $OSTYPE = darwin* ]]; then
  sed -i "/llvm/s/[a-z]*-x86_64/darwin-x86_64/" aosp/frameworks/native/libs/binder/rust/sys/build.rs
fi
