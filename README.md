# Android Keystore Client

Android keystore client written in Rust

## Development

### Requirements

- Andoird NDK
  - Install via Android SDK CLI: `sdkmanager --install 'ndk;27.2.12479018'`
- Android SDK Build-Tools
  - Install via Android SDK CLI: `sdkmanager --install 'build-tools;36.0.0'`
- Bash
- Clang
- GNU sed
- Rust
- Rust Android aarch64 target
  - Install via rustup: `rustup target add aarch64-linux-android`

### Build

```bash
git clone --recursive https://github.com/mikucat0309/keystore.git
cd keystore
./patch.sh
cargo build
```
