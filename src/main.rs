pub mod cli;
pub mod crypto;
pub mod error;

use anyhow::Result;
use clap::Parser;
use cli::{banner::show_banner, Command};
use crate::cli::Args;

fn main() -> Result<()> {
    let args = Args::parse();
    show_banner();
    Ok(args.execute()?)
}
