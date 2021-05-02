use crate::msgs::enums;

use hpke::{
    aead::{Aead, AeadCtxR, AeadCtxS, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait},
    kem::{DhP256HkdfSha256, Kem as KemTrait, X25519HkdfSha256},
    kex::KeyExchange,
    EncappedKey, OpModeS
};

use rand::{rngs::StdRng, SeedableRng};

const INFO_STR: &'static [u8] = b"example session";

fn setup<AEAD: Aead, KDF: KdfTrait, KEM: KemTrait>(msg: &[u8], associated_data: &[u8], server_pk: &<<KEM as KemTrait>::Kex as KeyExchange>::PublicKey)
-> (EncappedKey<<KEM as KemTrait>::Kex>, Vec<u8>, AeadTag<AEAD>) {
    let mut csprng = StdRng::from_entropy();

    // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
    // is what you use to encrypt.
    let (encapped_key, mut sender_ctx) =
        hpke::setup_sender::<AEAD, KDF, KEM, _>(&OpModeS::Base, server_pk, INFO_STR, &mut csprng)
            .expect("invalid server pubkey!");

    // On success, seal() will encrypt the plaintext in place
    let mut msg_copy = msg.to_vec();
    let tag = sender_ctx
        .seal(&mut msg_copy, associated_data)
        .expect("encryption failed!");

    // Rename for clarity
    let ciphertext = msg_copy;

    (encapped_key, ciphertext, tag)
}

/*
fn hpke_aead_from_tls(aead: enums::AEAD) -> impl Aead {
    match aead {
        enums::AEAD::AES_128_GCM =>
        enums::AEAD::AES_256_GCM =>
        enums::AEAD::CHACHA20_POLY_1305 =>
    }
}
*/