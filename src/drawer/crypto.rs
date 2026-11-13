//! MyPIN and Drawer RSA/AES primitives.
//! No Debug/serialization of PINs, derivation material or recovered private keys.
use crate::{Error, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
fn invalid() -> Error {
    Error::Invalid("Drawer key or encrypted data validation failed".into())
}
pub fn decode(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > 32 * 1024 * 1024 {
        return Err(invalid());
    }
    let normalized = Zeroizing::new(
        value
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    STANDARD
        .decode(&*normalized)
        .or_else(|_| STANDARD_NO_PAD.decode(&*normalized))
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}
pub struct Pin {
    text: Zeroizing<String>,
}
impl Pin {
    pub fn new(text: Zeroizing<String>) -> Result<Self> {
        if text.len() != 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Invalid(
                "My password requires exactly six digits".into(),
            ));
        }
        Ok(Self { text })
    }
    pub fn hashed(&self, salt: &str) -> Result<Zeroizing<String>> {
        let digest = self.digest(salt)?;
        Ok(Zeroizing::new(STANDARD.encode(&digest[..32])))
    }
    fn digest(&self, salt: &str) -> Result<Zeroizing<Vec<u8>>> {
        let salt = decode(salt)?;
        if salt.is_empty() {
            return Err(invalid());
        }
        let mut sha = Sha512::new();
        sha.update(self.text.as_bytes());
        sha.update(&*salt);
        Ok(Zeroizing::new(sha.finalize().to_vec()))
    }
    fn aes_key(&self, salt: &str, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        let salt = decode(salt)?;
        let password = decode(password)?;
        if salt.is_empty() || password.is_empty() {
            return Err(invalid());
        }
        let mut sha = Sha256::new();
        sha.update(self.text.as_bytes());
        sha.update(&*password);
        let password = Zeroizing::new(STANDARD.encode(sha.finalize()));
        let mut key = Zeroizing::new([0; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 4096, &mut *key);
        Ok(key)
    }
    pub fn recover(
        &self,
        salt: &str,
        password: &str,
        iv: &str,
        encrypted_key: &str,
        expected_hmac: &str,
    ) -> Result<DrawerKey> {
        let digest = self.digest(salt)?;
        let mut encrypted = decode(encrypted_key)?;
        let expected = decode(expected_hmac)?;
        let mut mac =
            <Hmac<sha1::Sha1> as Mac>::new_from_slice(&digest[32..]).map_err(|_| invalid())?;
        mac.update(&encrypted);
        mac.verify_slice(&expected).map_err(|_| invalid())?;
        let key = self.aes_key(salt, password)?;
        let iv = decode(iv)?;
        crypt_ctr(&key[..], &iv, &mut encrypted)?;
        DrawerKey::from_der(&encrypted)
    }
}
pub struct DrawerKey {
    rsa: RsaPrivateKey,
}
impl DrawerKey {
    pub(crate) fn private_der(&self) -> Result<rsa::pkcs8::SecretDocument> {
        use rsa::pkcs8::EncodePrivateKey;
        self.rsa.to_pkcs8_der().map_err(|_| invalid())
    }
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 16 * 1024 {
            return Err(invalid());
        }
        let rsa = RsaPrivateKey::from_pkcs8_der(bytes)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(bytes))
            .map_err(|_| invalid())?;
        rsa.validate().map_err(|_| invalid())?;
        Ok(Self { rsa })
    }
    pub fn decrypt(
        &self,
        secured_key: &str,
        iv: &str,
        enc_message: Option<&str>,
        enc_author: &str,
    ) -> Result<(Zeroizing<String>, i64)> {
        let key = self.unwrap(secured_key)?;
        decrypt_record(&key, iv, enc_message, enc_author)
    }
    fn unwrap(&self, secured_key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted = decode(secured_key)?;
        let unwrapped = Zeroizing::new(
            self.rsa
                .decrypt_blinded(
                    &mut rand::rngs::OsRng,
                    Oaep::new::<sha1::Sha1>(),
                    &encrypted,
                )
                .map_err(|_| invalid())?,
        );
        if !matches!(unwrapped.len(), 32 | 40 | 48) {
            return Err(invalid());
        }
        let length = unwrapped.len() - 16;
        let (key, checksum) = unwrapped.split_at(length);
        if !bool::from(md5::Md5::digest(key).as_slice().ct_eq(checksum)) {
            return Err(invalid());
        }
        Ok(Zeroizing::new(key.to_vec()))
    }
}
/// The official restore usecase caches secured keys. Bound the cache so unknown
/// key churn cannot retain memory proportional to the complete history.
pub struct RecordDecoder<'a> {
    key: &'a DrawerKey,
    cache: std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
}
impl<'a> RecordDecoder<'a> {
    pub fn new(key: &'a DrawerKey) -> Self {
        Self {
            key,
            cache: std::collections::HashMap::new(),
        }
    }
    pub fn decrypt(
        &mut self,
        secured_key: &str,
        iv: &str,
        message: Option<&str>,
        author: &str,
    ) -> Result<(Zeroizing<String>, i64)> {
        if !self.cache.contains_key(secured_key) {
            let key = self.key.unwrap(secured_key)?;
            if self.cache.len() >= 2048 {
                self.cache.clear();
            }
            self.cache.insert(secured_key.to_owned(), key);
        }
        decrypt_record(&self.cache[secured_key], iv, message, author)
    }
}
fn decrypt_record(
    key: &[u8],
    iv: &str,
    enc_message: Option<&str>,
    enc_author: &str,
) -> Result<(Zeroizing<String>, i64)> {
    let iv = decode(iv)?;
    let mut message = decode(enc_message.unwrap_or(""))?;
    let mut author = decode(enc_author)?;
    crypt_ctr(key, &iv, &mut message)?;
    crypt_ctr(key, &iv, &mut author)?;
    let message = Zeroizing::new(
        std::str::from_utf8(&message)
            .map_err(|_| invalid())?
            .to_owned(),
    );
    let author = std::str::from_utf8(&author)
        .map_err(|_| invalid())?
        .parse::<i64>()
        .map_err(|_| invalid())?;
    Ok((message, author))
}
fn crypt_ctr(key: &[u8], iv: &[u8], bytes: &mut [u8]) -> Result<()> {
    match key.len() {
        16 => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| invalid())?
            .apply_keystream(bytes),
        24 => ctr::Ctr128BE::<aes::Aes192>::new_from_slices(key, iv)
            .map_err(|_| invalid())?
            .apply_keystream(bytes),
        32 => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| invalid())?
            .apply_keystream(bytes),
        _ => return Err(invalid()),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_recovery_and_record_decryption_reject_wrong_integrity_material() {
        use rsa::pkcs8::EncodePrivateKey;
        let rsa = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let der = rsa.to_pkcs8_der().unwrap();
        let pin = Pin::new(Zeroizing::new("123456".into())).unwrap();
        let salt = STANDARD.encode(b"synthetic salt");
        let password = STANDARD.encode(b"synthetic server password");
        let iv = [3u8; 16];
        let mut encrypted = der.as_bytes().to_vec();
        crypt_ctr(
            &*pin.aes_key(&salt, &password).unwrap(),
            &iv,
            &mut encrypted,
        )
        .unwrap();
        let digest = pin.digest(&salt).unwrap();
        let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(&digest[32..]).unwrap();
        mac.update(&encrypted);
        let hmac = STANDARD.encode(mac.finalize().into_bytes());
        let encrypted = STANDARD.encode(encrypted);
        let iv64 = STANDARD.encode(iv);
        let key = pin
            .recover(&salt, &password, &iv64, &encrypted, &hmac)
            .unwrap();
        let wrong = Pin::new(Zeroizing::new("654321".into())).unwrap();
        assert!(wrong
            .recover(&salt, &password, &iv64, &encrypted, &hmac)
            .is_err());
        assert!(pin
            .recover(
                &salt,
                &password,
                &iv64,
                &encrypted,
                &STANDARD.encode([0u8; 20])
            )
            .is_err());
        let symmetric = [7u8; 32];
        let mut wrapped = symmetric.to_vec();
        wrapped.extend_from_slice(&md5::Md5::digest(symmetric));
        let secured = STANDARD.encode(
            rsa.to_public_key()
                .encrypt(&mut rand::rngs::OsRng, Oaep::new::<sha1::Sha1>(), &wrapped)
                .unwrap(),
        );
        let mut message = "합성 메시지".as_bytes().to_vec();
        let mut author = b"9007199254740993".to_vec();
        crypt_ctr(&symmetric, &iv, &mut message).unwrap();
        crypt_ctr(&symmetric, &iv, &mut author).unwrap();
        let message = STANDARD.encode(message);
        let author = STANDARD.encode(author);
        let (plain, id) = key
            .decrypt(&secured, &iv64, Some(&message), &author)
            .unwrap();
        assert_eq!(plain.as_str(), "합성 메시지");
        assert_eq!(id, 9007199254740993);
        assert_eq!(
            key.decrypt(&secured, &iv64, None, &author)
                .unwrap()
                .0
                .as_str(),
            ""
        );
        wrapped[47] ^= 1;
        let bad = STANDARD.encode(
            rsa.to_public_key()
                .encrypt(&mut rand::rngs::OsRng, Oaep::new::<sha1::Sha1>(), &wrapped)
                .unwrap(),
        );
        assert!(key.decrypt(&bad, &iv64, Some(&message), &author).is_err());
    }
    #[test]
    fn derivation_matches_independent_python_hashlib_fixture() {
        let pin = Pin::new(Zeroizing::new("123456".into())).unwrap();
        let salt = "c3ludGhldGljLXNhbHQ=";
        assert_eq!(
            pin.hashed(salt).unwrap().as_str(),
            "bdVoXhajg3YMAmvSAE0/0zCcUCkW0OWJJmgTeuqdQYA="
        );
        assert_eq!(
            hex::encode(
                *pin.aes_key(salt, "c3ludGhldGljLXNlcnZlci1wYXNzd29yZA==")
                    .unwrap()
            ),
            "1deddcb537ccb1dd687aceecc7dd416faa3751f68d9f2523d6cf890b81a23c4c"
        );
    }
    #[test]
    fn ctr_matches_nist_sp800_38a() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let mut value = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        crypt_ctr(&key, &iv, &mut value).unwrap();
        assert_eq!(hex::encode(value), "874d6191b620e3261bef6864990db6ce");
    }
    #[test]
    fn pin_format_and_rsa_corruption_are_rejected() {
        for value in ["12345", "1234567", "abcdef", "123 45"] {
            assert!(Pin::new(Zeroizing::new(value.into())).is_err());
        }
        assert!(DrawerKey::from_der(b"not a private key").is_err());
        assert!(decode("not_base64").is_err());
    }
}
