//! V2SL transport encryption with AES_GCM128 (type 3).
//! RSA public key is a public protocol constant, not an account credential.
use super::codec::{ProtocolError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use rsa::{BigUint, Oaep, RsaPublicKey};
use zeroize::Zeroizing;

pub const MAX_RECORD: usize = 131068;
pub const OVERHEAD: usize = 12 + 16;
pub const MAX_PLAINTEXT: usize = MAX_RECORD - OVERHEAD;
pub struct SecureLayer {
    key: Zeroizing<[u8; 16]>,
}
impl SecureLayer {
    pub(crate) fn copy_for_receive(&self) -> Self {
        Self {
            key: self.key.clone(),
        }
    }
    pub fn random() -> Self {
        let mut key = Zeroizing::new([0; 16]);
        OsRng.fill_bytes(&mut *key);
        Self { key }
    }
    pub fn handshake(&self) -> Result<Vec<u8>> {
        let modulus = BigUint::parse_bytes(include_str!("server-key.hex").trim().as_bytes(), 16)
            .ok_or(ProtocolError::KeyExchange)?;
        let public = RsaPublicKey::new(modulus, BigUint::from(3u32))
            .map_err(|_| ProtocolError::KeyExchange)?;
        let encrypted = public
            .encrypt(&mut OsRng, Oaep::new::<sha1::Sha1>(), &*self.key)
            .map_err(|_| ProtocolError::KeyExchange)?;
        let mut frame = Vec::with_capacity(12 + encrypted.len());
        frame.extend_from_slice(&(encrypted.len() as i32).to_le_bytes());
        frame.extend_from_slice(&16i32.to_le_bytes());
        frame.extend_from_slice(&3i32.to_le_bytes());
        frame.extend_from_slice(&encrypted);
        Ok(frame)
    }
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0; 12];
        OsRng.fill_bytes(&mut iv);
        self.encrypt_with_iv(plaintext, &iv)
    }
    fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(ProtocolError::Size);
        }
        let cipher =
            Aes128Gcm::new_from_slice(&*self.key).map_err(|_| ProtocolError::KeyExchange)?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(iv), plaintext)
            .map_err(|_| ProtocolError::Authentication)?;
        let mut frame = Vec::with_capacity(4 + 12 + encrypted.len());
        frame.extend_from_slice(&((12 + encrypted.len()) as i32).to_le_bytes());
        frame.extend_from_slice(iv);
        frame.extend_from_slice(&encrypted);
        Ok(frame)
    }
    pub fn decrypt(&self, record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if record.len() < OVERHEAD || record.len() > MAX_RECORD {
            return Err(ProtocolError::Size);
        }
        let cipher =
            Aes128Gcm::new_from_slice(&*self.key).map_err(|_| ProtocolError::KeyExchange)?;
        cipher
            .decrypt(Nonce::from_slice(&record[..12]), &record[12..])
            .map(Zeroizing::new)
            .map_err(|_| ProtocolError::Authentication)
    }
    pub fn record_length(prefix: [u8; 4]) -> Result<usize> {
        let len = i32::from_le_bytes(prefix);
        if !(OVERHEAD as i32..=MAX_RECORD as i32).contains(&len) {
            return Err(ProtocolError::Size);
        }
        Ok(len as usize)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nist_gcm_vector_and_tampering() {
        let layer = SecureLayer {
            key: Zeroizing::new([0; 16]),
        };
        let frame = layer.encrypt_with_iv(&[0; 16], &[0; 12]).unwrap();
        // NIST SP800-38D AES128 all-zero key/IV/plaintext test vector.
        assert_eq!(
            hex::encode(&frame[16..]),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
        );
        assert_eq!(*layer.decrypt(&frame[4..]).unwrap(), vec![0; 16]);
        let mut bad = frame[4..].to_vec();
        bad[12] ^= 1;
        assert_eq!(
            layer.decrypt(&bad).err().unwrap(),
            ProtocolError::Authentication
        );
        for n in [i32::MIN, -1, 0, 27, 131069] {
            assert!(SecureLayer::record_length(n.to_le_bytes()).is_err());
        }
    }
    #[test]
    fn handshake_and_random_ivs_have_expected_shapes() {
        let layer = SecureLayer::random();
        let frame = layer.handshake().unwrap();
        assert_eq!(frame.len(), 268);
        assert_eq!(&frame[..12], &[0, 1, 0, 0, 16, 0, 0, 0, 3, 0, 0, 0]);
        let a = layer.encrypt(b"synthetic-message").unwrap();
        let b = layer.encrypt(b"synthetic-message").unwrap();
        assert_ne!(&a[4..16], &b[4..16]);
        assert_eq!(
            layer.decrypt(&a[4..]).unwrap().as_slice(),
            b"synthetic-message"
        );
    }
}
