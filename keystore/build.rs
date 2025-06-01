use std::env;

fn main() {
    println!(
        "cargo::rustc-link-search={}/lib/{}",
        env::current_dir().unwrap().to_str().unwrap(),
        env::var("TARGET").unwrap()
    );
}
