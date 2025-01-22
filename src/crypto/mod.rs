mod utils;

use crate::error::KapsError;
use anyhow::Context;
use std::path::Path;

pub use utils::{decrypt_directory, encrypt_directory, validate_password};