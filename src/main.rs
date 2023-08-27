use std::{env, fs, path::Path};

use anyhow::Result;
use pkcs8::{
    der::pem::PemLabel,
    pkcs5::{pbes2, scrypt},
    EncodePrivateKey, EncryptedPrivateKeyInfo, LineEnding, PrivateKeyInfo,
};
use rand::RngCore;
use rsa::RsaPrivateKey;

const PASSWORD: &str = "password";

fn write_with_default_params(path: &Path, key: &RsaPrivateKey) -> Result<()> {
    let mut rng = rand::thread_rng();
    let data = key.to_pkcs8_encrypted_pem(&mut rng, PASSWORD, LineEnding::LF)?;

    fs::write(path, data)?;

    Ok(())
}

/// Write using the same scrypt params as `openssl pkcs8`'s defaults.
fn write_with_openssl_params(path: &Path, key: &RsaPrivateKey) -> Result<()> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // 14 = log_2(16384), 32 bytes = 256 bits
    let scrypt_params = scrypt::Params::new(14, 8, 1, 32).unwrap();
    let pbes2_params = pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv).unwrap();

    let plain_text_der = key.to_pkcs8_der().unwrap();
    let private_key_info = PrivateKeyInfo::try_from(plain_text_der.as_bytes())?;

    let secret_doc = private_key_info.encrypt_with_params(pbes2_params, PASSWORD)?;

    let encrypted_pem = secret_doc.to_pem(EncryptedPrivateKeyInfo::PEM_LABEL, LineEnding::LF)?;

    fs::write(path, encrypted_pem)?;

    Ok(())
}

fn main() -> Result<()> {
    let mut args_iter = env::args_os().skip(1);
    let path_default_params = args_iter.next().unwrap();
    let path_openssl_params = args_iter.next().unwrap();

    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 4096).unwrap();

    write_with_default_params(Path::new(&path_default_params), &key)?;
    write_with_openssl_params(Path::new(&path_openssl_params), &key)?;

    Ok(())
}
