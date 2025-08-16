use wasm_bindgen::prelude::*;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use aes_gcm::{
    // ИСПРАВЛЕНИЕ #1: Добавляем трейт `AeadCore`, чтобы была доступна `generate_nonce`
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64ct::{Base64, Encoding};
// ИСПРАВЛЕНИЕ #2: Импортируем `GenericArray` для преобразования типов
use elliptic_curve::generic_array::GenericArray;

// --- УПРАВЛЕНИЕ КЛЮЧАМИ ---

#[wasm_bindgen]
pub fn generate_keypair_base64() -> Vec<String> {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let secret_b64 = Base64::encode_string(secret_key.to_bytes().as_slice());
    let public_b64 = Base64::encode_string(public_key.to_sec1_bytes().as_ref());

    vec![secret_b64, public_b64]
}

// --- ШИФРОВАНИЕ И РАСШИФРОВКА ---

#[wasm_bindgen]
pub fn encrypt(my_secret_key_b64: &str, their_public_key_b64: &str, plaintext: &str) -> Result<String, JsValue> {
    // 1. Декодируем ключи
    let secret_bytes = Base64::decode_vec(my_secret_key_b64).map_err(|e| e.to_string())?;
    // ИСПРАВЛЕНИЕ #3: Преобразуем Vec<u8> в GenericArray нужного типа
    let secret_key = SecretKey::from_bytes(GenericArray::from_slice(&secret_bytes)).map_err(|e| e.to_string())?;
    
    let public_bytes = Base64::decode_vec(their_public_key_b64).map_err(|e| e.to_string())?;
    let public_key = PublicKey::from_sec1_bytes(&public_bytes).map_err(|e| e.to_string())?;

    // 2. Вычисляем общий секрет
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    
    // ИСПРАВЛЕНИЕ #4: Явно копируем байты из GenericArray в обычный массив
    let key = shared_secret.raw_secret_bytes();
    let key_array: [u8; 32] = key.as_slice().try_into().expect("Incorrect key size");

    // 3. Шифруем
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_array));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| e.to_string())?;
    
    // 4. Объединяем и кодируем
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(Base64::encode_string(&result))
}

#[wasm_bindgen]
pub fn decrypt(my_secret_key_b64: &str, their_public_key_b64: &str, ciphertext_b64: &str) -> Result<String, JsValue> {
    // 1. Декодируем ключи
    let secret_bytes = Base64::decode_vec(my_secret_key_b64).map_err(|e| e.to_string())?;
    // ИСПРАВЛЕНИЕ #3 (повторяем)
    let secret_key = SecretKey::from_bytes(GenericArray::from_slice(&secret_bytes)).map_err(|e| e.to_string())?;
    
    let public_bytes = Base64::decode_vec(their_public_key_b64).map_err(|e| e.to_string())?;
    let public_key = PublicKey::from_sec1_bytes(&public_bytes).map_err(|e| e.to_string())?;

    // 2. Вычисляем общий секрет
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    
    // ИСПРАВЛЕНИЕ #4 (повторяем)
    let key = shared_secret.raw_secret_bytes();
    let key_array: [u8; 32] = key.as_slice().try_into().expect("Incorrect key size");
    
    // 3. Декодируем сообщение
    let data = Base64::decode_vec(ciphertext_b64).map_err(|e| e.to_string())?;
    if data.len() < 12 { return Err("Invalid ciphertext".into()); }
    
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // 4. Расшифровываем
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_array));
    let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    
    String::from_utf8(plaintext_bytes).map_err(|e| e.to_string().into())
}