#!/usr/bin/env bash
set -e

INSTALL_PATH="/data/local/tmp/keystore"
adb shell rm -f $INSTALL_PATH
adb push target/aarch64-linux-android/debug/keystore $INSTALL_PATH
adb shell chmod 755 $INSTALL_PATH
