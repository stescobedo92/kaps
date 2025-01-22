pub mod banner;

use crate::{crypto, error::KapsError};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "kaps",
    version,
    about = "🔒 Enterprise File Vault with AES-256-CBC",
    long_about = None,
    help_template = r#"
{before-help}{name} {version}
{about}

USAGE:
  {usage}

COMMANDS:
{all-args}{after-help}"#
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

impl Args {
    pub fn execute(self) -> Result<(), KapsError> {
        match self.command {
            Command::Encrypt {
                input,
                output,
                password,
            } => crypto::encrypt_directory(&input, &output, &password),
            Command::Decrypt {
                input,
                output,
                password,
            } => crypto::decrypt_directory(&input, &output, &password),
        }
    }
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// 🔐 Encrypt directory structure (AES-256-CBC)
    Encrypt {
        /// Source directory with plaintext files
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Target directory for encrypted vault
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,

        /// Encryption passphrase (min 12 chars)
        #[arg(short, long, hide = true)]
        password: String,
    },

    /// 🔓 Decrypt protected vault
    Decrypt {
        /// Encrypted vault directory
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Output directory for decrypted files
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,

        /// Decryption passphrase
        #[arg(short, long, hide = true)]
        password: String,
    },
}