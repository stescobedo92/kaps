use anyhow::Result;
use kaps::{crypto, error::KapsError};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_full_cycle() -> Result<()> {
    let input_dir = TempDir::new()?;
    let encrypted_dir = TempDir::new()?;
    let decrypted_dir = TempDir::new()?;
    let password = "ValidPass123!";

    // Create test file
    std::fs::write(input_dir.path().join("test.txt"), "secret data")?;

    // Encrypt
    crypto::encrypt_directory(input_dir.path(), encrypted_dir.path(), password)?;

    // Decrypt
    crypto::decrypt_directory(encrypted_dir.path(), decrypted_dir.path(), password)?;

    // Verify
    let decrypted_content = std::fs::read_to_string(decrypted_dir.path().join("test.txt"))?;
    assert_eq!(decrypted_content, "secret data");

    Ok(())
}

#[test]
fn test_invalid_password() {
    let dir = TempDir::new().unwrap();
    let password = "ValidPass123!";
    let wrong_password = "WrongPass123!";

    crypto::encrypt_directory(dir.path(), dir.path(), password).unwrap();
    let result = crypto::decrypt_directory(dir.path(), dir.path(), wrong_password);

    assert!(matches!(
        result.unwrap_err(),
        KapsError::Crypto(_)
    ));
}