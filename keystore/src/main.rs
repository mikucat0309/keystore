use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::{Parser, Subcommand};
use keystore::rsa;

#[derive(Parser)]
#[command(version, about = "Android keystore client")]
pub struct MainCommand {
    #[command(subcommand)]
    pub sub: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    List,
    Delete {
        // key alias
        #[arg(short, long)]
        alias: String,
    },
    GenRsa {
        // key alias
        #[arg(short, long)]
        alias: String,

        #[command(flatten)]
        args: rsa::GenerateParams,
    },
    EncRsa {
        // key alias
        #[arg(short, long)]
        alias: String,

        // input file
        #[arg(short, long, value_name = "FILE")]
        in_file: PathBuf,

        // output file
        #[arg(short, long, value_name = "FILE")]
        out_file: PathBuf,

        #[command(flatten)]
        args: rsa::CryptParams,
    },
    DecRsa {
        // key alias
        #[arg(short, long)]
        alias: String,

        // input file
        #[arg(short, long)]
        in_file: PathBuf,

        // output file
        #[arg(short, long)]
        out_file: PathBuf,

        #[command(flatten)]
        args: rsa::CryptParams,
    },
}

fn base64_read(in_file: &PathBuf) -> Result<Vec<u8>> {
    let input_b64 = fs::read(in_file)?;
    let input = BASE64_STANDARD
        .decode(input_b64)
        .context("Failed to decode from base64.")?;
    Ok(input)
}

fn base64_write(out_file: &PathBuf, output: &[u8]) -> Result<()> {
    fs::write(out_file, BASE64_STANDARD.encode(output)).context("Failed to encode to base64.")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = MainCommand::parse();
    match args.sub {
        SubCommands::List => {
            let keys = keystore::list()?;
            for key in &keys {
                let alias = key.alias.as_deref().unwrap_or("<no alias>");
                println!("{alias}");
            }
        }
        SubCommands::Delete { alias } => {
            keystore::delete_with_alias(&alias)?;
        }
        SubCommands::GenRsa { alias, args } => {
            rsa::generate_with_alias(&alias, &args)?;
        }
        SubCommands::EncRsa {
            alias,
            in_file,
            out_file,
            args,
        } => {
            let input = base64_read(&in_file)?;
            let output = rsa::encrypt_with_alias(&alias, &args, &input)?;
            base64_write(&out_file, &output)?;
        }
        SubCommands::DecRsa {
            alias,
            in_file,
            out_file,
            args,
        } => {
            let input = base64_read(&in_file)?;
            let output = rsa::decrypt_with_alias(&alias, &args, &input)?;
            base64_write(&out_file, &output)?;
        }
    }
    Ok(())
}
