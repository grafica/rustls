use crate::msgs::base::{PayloadU16, PayloadU8, Payload};
use crate::msgs::enums::*;
use crate::msgs::handshake::*;
use crate::msgs::codec::{Codec, Reader};
use base64;
use webpki::DnsNameRef;

#[test]
fn test_echconfig_serialization() {
    // An ECHConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
    let base64_echconfigs = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
    let bytes = base64::decode(&base64_echconfigs).unwrap();
    let configs = ECHConfigList::read(&mut Reader::init(&bytes)).unwrap();
    assert_eq!(configs.len(), 1);
    let config: &ECHConfig = &configs[0];
    assert_eq!(config.version, ECHVersion::V10);
    let name = String::from_utf8(
        config
            .contents
            .public_name
            .clone()
            .into_inner(),
    )
    .unwrap();
    assert_eq!("cloudflare-esni.com", name.as_str());
    assert_eq!(
        config
            .contents
            .hpke_key_config
            .hpke_kem_id,
        KEM::DHKEM_X25519_HKDF_SHA256
    );
    assert_eq!(
        config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites
            .len(),
        1
    );
    assert_eq!(
        config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites[0]
            .hpke_kdf_id,
        KDF::HKDF_SHA256
    );
    assert_eq!(
        config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites[0]
            .hpke_aead_id,
        AEAD::AES_128_GCM
    );
    let mut output = Vec::new();
    configs.encode(&mut output);
    assert_eq!(base64_echconfigs, base64::encode(&output));
}

// TODO: tests for "Section 4.1. Configuration Extensions"

#[allow(dead_code)]
fn get_sample_clienthellopayload() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionID::empty(),
        cipher_suites: vec![CipherSuite::TLS_NULL_WITH_NULL_NULL],
        compression_methods: vec![Compression::Null],
        extensions: vec![
            ClientExtension::ECPointFormats(ECPointFormatList::supported()),
            ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientExtension::make_sni(DnsNameRef::try_from_ascii_str("inner-sni.example.com").unwrap()),
            ClientExtension::SessionTicketRequest,
            ClientExtension::SessionTicketOffer(Payload(vec![])),
            ClientExtension::Protocols(vec![PayloadU8(vec![0])]),
            ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3])]),
            ClientExtension::PresharedKeyModes(vec![PSKKeyExchangeMode::PSK_DHE_KE]),
            ClientExtension::PresharedKey(PresharedKeyOffer {
                identities: vec![
                    PresharedKeyIdentity::new(vec![3, 4, 5], 123456),
                    PresharedKeyIdentity::new(vec![6, 7, 8], 7891011),
                ],
                binders: vec![
                    PresharedKeyBinder::new(vec![1, 2, 3]),
                    PresharedKeyBinder::new(vec![3, 4, 5]),
                ],
            }),
            ClientExtension::Cookie(PayloadU16(vec![1, 2, 3])),
            ClientExtension::ExtendedMasterSecretRequest,
            ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
            ClientExtension::SignedCertificateTimestampRequest,
            ClientExtension::TransportParameters(vec![1, 2, 3]),
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(12345),
                payload: Payload(vec![1, 2, 3]),
            }),
        ],
    }
}