# Android Keystore Client

Android keystore client written in Rust

## Development

### Requirements

- Andoird NDK
  - Install via Android SDK CLI: `sdkmanager --install 'ndk;27.2.12479018'`
- AIDL compiler
  - Install via Android SDK CLI: `sdkmanager --install 'build-tools;36.0.0'`
- Bash
- Clang
- GNU sed
- Rust
- Rust Android aarch64 target
  - Install via rustup: `rustup target add aarch64-linux-android`

### Build

1. Clone this repository

   ```bash
   git clone --recursive https://github.com/mikucat0309/keystore.git
   cd keystore
   ```
2. Patch libbinder-rs

   ```bash
   ./patch.sh
   ```

3. Setup below environment variables in [.cargo/config.toml](.cargo/config.toml) or export in yuor shell

   - `ANDROID_NDK_HOME`: Android NDK home path
   - `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`: Android NDK linker path

4. Build

   ```bash
   cargo build
   ```
