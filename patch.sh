#!/usr/bin/env bash
set -e

patch="$(pwd)/patch"
cd aosp/frameworks/native

git apply "$patch/0001-generate-stub-binder_ndk.patch"

if [[ $OSTYPE = darwin* ]]; then
  git apply "$patch/0002-fix-toolchain-path-for-macOS.patch"
fi
