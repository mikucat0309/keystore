use std::io::{self, Error};
use std::path::PathBuf;
use std::process::Command;

use glob::glob;

#[derive(Clone)]
pub struct Source {
    pub dir: PathBuf,
    pub package: String,
    pub version: String,
}

impl Source {
    pub fn aidl_path(&self) -> String {
        format!(
            "{}/aidl_api/{}/{}",
            self.dir.to_str().unwrap(),
            self.package,
            self.version
        )
    }
}

#[derive(Clone)]
pub struct Builder {
    args: Vec<String>,
    includes: Vec<Source>,
    source_dir: PathBuf,
    output_dir: PathBuf,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
            includes: Vec::new(),
            source_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
        }
    }

    pub fn arg(&mut self, arg: &str) -> &mut Self {
        self.args.push(arg.to_owned());
        self
    }

    pub fn args<S, I>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in args {
            self.arg(s.as_ref());
        }
        self
    }

    pub fn include(&mut self, src: &Source) -> &mut Self {
        assert!(src.dir.ends_with("aidl"));
        self.includes.push(src.to_owned());
        self
    }

    pub fn includes<'a, I>(&mut self, srcs: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a Source>,
    {
        for s in srcs {
            self.include(s);
        }
        self
    }

    pub fn source(&mut self, src: &Source) -> &mut Self {
        assert!(src.dir.is_dir());
        self.source_dir = PathBuf::from(src.aidl_path());
        self
    }

    pub fn output(&mut self, dir: &PathBuf) -> &mut Self {
        self.output_dir = dir.to_owned();
        self
    }

    pub fn generate(&self) -> Result<(), io::Error> {
        self.generate_aidl()?;
        self.glue_aidl()?;
        Ok(())
    }

    fn generate_aidl(&self) -> Result<(), io::Error> {
        let include_args: Vec<String> = self
            .includes
            .iter()
            .map(|x| x.aidl_path())
            .map(|x| format!("--include={x}"))
            .collect();
        let paths: Vec<PathBuf> = glob(&format!("{}/**/*.aidl", self.source_dir.to_str().unwrap()))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();

        let status = Command::new("aidl")
            .arg(format!("--out={}", self.output_dir.to_str().unwrap()))
            .args(include_args)
            .args(&self.args)
            .args(&paths)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::other(format!(
                "failed with exit code: {}",
                status.code().unwrap()
            )))
        }
    }

    fn glue_aidl(&self) -> Result<(), io::Error> {
        let output_file = PathBuf::from("src/generated.rs");
        let root_dir = &self.output_dir;
        let import_args: Vec<String> = self
            .includes
            .iter()
            .skip(1)
            .map(|x| x.package.replace(".", "_"))
            .map(|x| format!("--import={x}"))
            .collect();
        let paths: Vec<PathBuf> = glob(&format!("{}/**/*.rs", self.output_dir.to_str().unwrap()))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        let status = Command::new("python3")
            .arg("../../aosp/system/tools/aidl/build/aidl_rust_glue.py")
            .arg(output_file)
            .arg(root_dir)
            .args(import_args)
            .args(paths)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::other(format!(
                "failed with exit code: {}",
                status.code().unwrap()
            )))
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
