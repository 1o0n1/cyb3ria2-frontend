use wasm_bindgen::prelude::*;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64ct::{Base64, Encoding};
use elliptic_curve::generic_array::GenericArray;
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};
use rand::RngCore;

// --- Функции без изменений ---

#[wasm_bindgen]
pub fn generate_keypair_base64() -> Vec<String> {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let secret_b64 = Base64::encode_string(secret_key.to_bytes().as_slice());
    let public_b64 = Base64::encode_string(public_key.to_sec1_bytes().as_ref());
    vec![secret_b64, public_b64]
}

#[wasm_bindgen]
pub fn encrypt(my_secret_key_b64: &str, their_public_key_b64: &str, plaintext: &str) -> Result<String, JsValue> {
    let secret_bytes = Base64::decode_vec(my_secret_key_b64).map_err(|e| e.to_string())?;
    let secret_key = SecretKey::from_bytes(GenericArray::from_slice(&secret_bytes)).map_err(|e| e.to_string())?;
    let public_bytes = Base64::decode_vec(their_public_key_b64).map_err(|e| e.to_string())?;
    let public_key = PublicKey::from_sec1_bytes(&public_bytes).map_err(|e| e.to_string())?;

    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let key: &[u8; 32] = shared_secret.raw_secret_bytes().as_ref();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| e.to_string())?;
    
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(Base64::encode_string(&result))
}

#[wasm_bindgen]
pub fn decrypt(my_secret_key_b64: &str, their_public_key_b64: &str, ciphertext_b64: &str) -> Result<String, JsValue> {
    let secret_bytes = Base64::decode_vec(my_secret_key_b64).map_err(|e| e.to_string())?;
    let secret_key = SecretKey::from_bytes(GenericArray::from_slice(&secret_bytes)).map_err(|e| e.to_string())?;
    let public_bytes = Base64::decode_vec(their_public_key_b64).map_err(|e| e.to_string())?;
    let public_key = PublicKey::from_sec1_bytes(&public_bytes).map_err(|e| e.to_string())?;
    
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let key: &[u8; 32] = shared_secret.raw_secret_bytes().as_ref();
    
    let data = Base64::decode_vec(ciphertext_b64).map_err(|e| e.to_string())?;
    if data.len() < 12 { return Err("Invalid ciphertext".into()); }
    
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    
    String::from_utf8(plaintext_bytes).map_err(|e| e.to_string().into())
}

// --- Функции с исправлениями ---

const PBKDF2_ROUNDS: u32 = 600_000;

#[wasm_bindgen]
pub fn encrypt_with_password(password: &str, plaintext: &str) -> Result<String, JsValue> {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    // ИСПРАВЛЕНИЕ #1: Убираем warning, используя новую функцию
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| e.to_string())?;

    let password_hash = Pbkdf2.hash_password_customized(
        password.as_bytes(), None, None, pbkdf2::Params { rounds: PBKDF2_ROUNDS, output_length: 32 }, &salt,
    ).map_err(|e| e.to_string())?;

    // ИСПРАВЛЕНИЕ #2: Решаем проблему времени жизни
    let password_hash_output = password_hash.hash.ok_or("Failed to get hash bytes")?;
    let key: &[u8; 32] = password_hash_output.as_bytes().try_into().map_err(|_| "Invalid key length")?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| e.to_string())?;

    let mut result = salt_bytes.to_vec();
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    Ok(Base64::encode_string(&result))
}

#[wasm_bindgen]
pub fn decrypt_with_password(password: &str, encrypted_b64: &str) -> Result<String, JsValue> {
    let data = Base64::decode_vec(encrypted_b64).map_err(|e| e.to_string())?;
    if data.len() < 16 + 12 { return Err("Invalid encrypted data".into()); }

    let (salt_bytes, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    // ИСПРАВЛЕНИЕ #1: Убираем warning, используя новую функцию
    let salt = SaltString::encode_b64(salt_bytes).map_err(|e| e.to_string())?;

    let password_hash = Pbkdf2.hash_password_customized(
        password.as_bytes(), None, None, pbkdf2::Params { rounds: PBKDF2_ROUNDS, output_length: 32 }, &salt,
    ).map_err(|e| e.to_string())?;

    // ИСПРАВЛЕНИЕ #2: Решаем проблему времени жизни
    let password_hash_output = password_hash.hash.ok_or("Failed to get hash bytes")?;
    let key: &[u8; 32] = password_hash_output.as_bytes().try_into().map_err(|_| "Invalid key length")?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;

    String::from_utf8(plaintext_bytes).map_err(|e| e.to_string().into())
}