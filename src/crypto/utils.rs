use crate::error::KapsError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, BlockCipher, generic_array::typenum::Unsigned, consts::U16};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use anyhow::Context;
use walkdir::WalkDir;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const SALT_FILE: &str = ".salt";
const SALT_LENGTH: usize = 16;
const IV_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Validates password against NIST SP 800-63B guidelines
pub fn validate_password(password: &str) -> Result<(), KapsError> {
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if password.len() < 12 {
        Err(KapsError::PasswordValidation("Password must be at least 12 characters".into()))
    } else if !has_upper {
        Err(KapsError::PasswordValidation("Password must contain at least one uppercase letter".into()))
    } else if !(has_digit || has_special) {
        Err(KapsError::PasswordValidation("Password must contain at least one number or special character".into()))
    } else {
        Ok(())
    }
}

/// Encrypts directory recursively with AES-256-CBC
pub fn encrypt_directory(input_dir: &Path, output_dir: &Path, password: &str) -> Result<(), KapsError> {
    validate_password(password)?;

    fs::create_dir_all(output_dir).context("Failed to create output directory")?;

    let salt = generate_salt(output_dir)?;
    let key = derive_key(password, &salt);

    process_directory(input_dir, output_dir, |plaintext, iv| perform_encryption(plaintext, &key, iv), Some(salt))
}

/// Decrypts directory recursively
pub fn decrypt_directory(input_dir: &Path, output_dir: &Path, password: &str) -> Result<(), KapsError> {
    let salt = read_salt(input_dir)?;
    let key = derive_key(password, &salt);

    process_directory(input_dir, output_dir, |ciphertext, iv| perform_decryption(ciphertext, &key, iv),None)
}

// -- Internal implementation details --

fn generate_salt(output_dir: &Path) -> Result<[u8; SALT_LENGTH], KapsError> {
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().try_fill_bytes(&mut salt).context("Failed to generate salt")?;

    fs::write(output_dir.join(SALT_FILE), &salt).context("Failed to write salt file")?;

    Ok(salt)
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS,&mut key).expect("TODO: panic message");

    key
}

fn process_directory<F>(input_dir: &Path, output_dir: &Path, crypto_op: F, salt: Option<[u8; SALT_LENGTH]>) -> Result<(), KapsError> where F: Fn(&[u8], &[u8; IV_LENGTH]) -> Result<Vec<u8>, KapsError>,
{
    for entry in WalkDir::new(input_dir) {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let relative_path = path.strip_prefix(input_dir).context("Failed to get relative path")?;
        let output_path = output_dir.join(relative_path);

        if path.is_dir() {
            fs::create_dir_all(&output_path).context("Failed to create output directory")?;
        } else if path.file_name().unwrap() != SALT_FILE || salt.is_some() {
            process_file(path, &output_path, &crypto_op).context("Failed to process file")?;
        }
    }
    Ok(())
}

fn process_file<F>(input_path: &Path,output_path: &Path,crypto_op: &F) -> Result<(), KapsError> where F: Fn(&[u8], &[u8; IV_LENGTH]) -> Result<Vec<u8>, KapsError>,
{
    let mut iv = [0u8; IV_LENGTH];
    rand::thread_rng().try_fill_bytes(&mut iv).context("Failed to generate IV")?;

    let mut input_file = File::open(input_path).context("Failed to open input file")?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer).context("Failed to read input file")?;

    let processed_data = crypto_op(&buffer, &iv).context("Crypto operation failed")?;

    let mut output_file = File::create(output_path).context("Failed to create output file")?;
    output_file.write_all(&iv).context("Failed to write IV")?;
    output_file.write_all(&processed_data).context("Failed to write processed data")?;

    Ok(())
}

fn perform_encryption(plaintext: &[u8], key: &[u8; KEY_LENGTH],iv: &[u8; IV_LENGTH]) -> Result<Vec<u8>, KapsError> {
    let mut buffer = vec![0u8; plaintext.len() + U16::USIZE];
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    let cipher = Aes256CbcEnc::new_from_slices(key, iv)?;
    let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len()).map_err(|e| KapsError::Crypto(e.to_string()))?;

    Ok(ciphertext.to_vec())
}

fn perform_decryption(ciphertext: &[u8], key: &[u8; KEY_LENGTH], iv: &[u8; IV_LENGTH]) -> Result<Vec<u8>, KapsError> {
    let mut buffer = ciphertext.to_vec();
    let cipher = Aes256CbcDec::new_from_slices(key, iv)?;
    let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).map_err(|e| KapsError::Crypto(e.to_string()))?;

    Ok(plaintext.to_vec())
}

fn read_salt(input_dir: &Path) -> Result<[u8; SALT_LENGTH], KapsError> {
    let salt_path = input_dir.join(SALT_FILE);
    let salt = fs::read(&salt_path).context("Salt file not found")?;

    if salt.len() != SALT_LENGTH {
        return Err(KapsError::FileFormat(format!("Invalid salt length: expected {}, got {}", SALT_LENGTH,salt.len())));
    }

    let mut salt_array = [0u8; SALT_LENGTH];
    salt_array.copy_from_slice(&salt);
    Ok(salt_array)
}

// Helper function para crear estructura de directorios de prueba
fn create_test_structure(root: &Path) -> PathBuf {
    let subdir = root.join("subdir");
    fs::create_dir(&subdir).unwrap();

    let files = vec![
        root.join("file1.txt"),
        root.join("file2.dat"),
        subdir.join("file3.bin"),
    ];

    for file in files {
        fs::write(file, "test data").unwrap();
    }

    root.to_path_buf()
}

#[cfg(test)]
mod integration_tests {
    use super::{encrypt_directory, decrypt_directory, read_salt, create_test_structure};
    use crate::error::KapsError;
    use tempfile::TempDir;
    use std::fs;
    use crate::crypto;

    #[test]
    fn test_password_validation() {
        let cases = vec![
            ("Short1!", "at least 12 characters"),
            ("nouppercase123!", "uppercase letter"),
            ("NoDigitsOrSpecials", "number or special character"),
            ("ValidPass123!", ""), // Caso válido
        ];

        for (input, expected_error) in cases {
            let result = crypto::validate_password(input);

            if expected_error.is_empty() {
                assert!(result.is_ok(), "Failed valid password: {}", input);
            } else {
                match result {
                    Err(KapsError::PasswordValidation(msg)) =>
                        assert!(msg.contains(expected_error), "Unexpected error: {}", msg),
                    _ => panic!("Unexpected result for: {}", input),
                }
            }
        }
    }

    #[test]
    fn test_encrypted_data_integrity() -> Result<(), KapsError> {
        let original_dir = TempDir::new()?;
        let encrypted_dir = TempDir::new()?;
        let password = "MyStrongPassword!";

        fs::write(original_dir.path().join("data.bin"), vec![0u8; 1024])?;

        crypto::encrypt_directory(original_dir.path(), encrypted_dir.path(), password)?;

        // Verificar que los archivos encriptados son diferentes
        let original = fs::read(original_dir.path().join("data.bin"))?;
        let encrypted = fs::read(encrypted_dir.path().join("data.bin"))?;

        assert_ne!(original, encrypted, "Encrypted data matches original");
        assert!(encrypted.len() > original.len(), "Encrypted size mismatch");

        Ok(())
    }
}