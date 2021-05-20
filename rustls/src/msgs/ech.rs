use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientExtension::EchOuterExtensions;
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, EchConfig, EchConfigContents, EchConfigList,
    HpkeSymmetricCipherSuite, Random, SessionID,
};
use crate::rand;
use crate::Error;
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use webpki;

#[allow(dead_code)]
const HPKE_INFO: &[u8; 8] = b"tls ech\0";

fn hpke_info(config: &EchConfig) -> Vec<u8> {
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(HPKE_INFO);
    config.encode(&mut info);
    info
}

#[allow(dead_code)]
pub struct EncryptedClientHello {
    pub hostname: webpki::DnsName,
    pub hpke: Hpke,
    pub hpke_info: Vec<u8>,
    pub suite: HpkeSymmetricCipherSuite,
    pub config_contents: EchConfigContents,
    pub encoded_inner: Option<Vec<u8>>,
    pub inner_random: [u8; 32],
    /// Extensions that will be referenced in the ClientHelloOuter by the EncryptedClientHelloInner.
    pub compressed_extensions: Vec<ExtensionType>,
    // outer_only_exts?
}

impl EncryptedClientHello {
    pub fn with_host_and_config_list(
        name: webpki::DnsNameRef,
        config_bytes: &Vec<u8>,
    ) -> Result<EncryptedClientHello, Error> {
        let configs: EchConfigList = EchConfigList::read(&mut Reader::init(config_bytes))
            .ok_or_else(|| Error::General("Couldn't parse ECH record.".to_string()))?;
        let (config_contents, hpke_info, (suite, hpke)) = configs
            .iter()
            .find_map(|config| {
                Some((
                    config.contents.clone(),
                    hpke_info(&config),
                    config
                        .contents
                        .hpke_key_config
                        .hpke_symmetric_cipher_suites
                        .iter()
                        .find_map(|suite| {
                            Some((
                                suite,
                                hpke_rs::Hpke::new(
                                    Mode::Base,
                                    HpkeKemMode::try_from(
                                        config
                                            .contents
                                            .hpke_key_config
                                            .hpke_kem_id
                                            .get_u16(),
                                    )
                                    .ok()?,
                                    HpkeKdfMode::try_from(suite.hpke_kdf_id.get_u16()).ok()?,
                                    HpkeAeadMode::try_from(suite.hpke_aead_id.get_u16()).ok()?,
                                ),
                            ))
                        })?,
                ))
            })
            .ok_or(Error::NoHpkeConfig)?;

        // TODO: check for unknown mandatory extensions in config_contents (Section 4.1)
        // Clients MUST parse the extension list and check for unsupported mandatory extensions.
        // If an unsupported mandatory extension is present, clients MUST ignore the ECHConfig.

        let mut inner_random = [0u8; 32];
        rand::fill_random(&mut inner_random)?;

        Ok(EncryptedClientHello {
            hostname: name.to_owned(),
            hpke,
            hpke_info,
            suite: suite.clone(),
            config_contents,
            encoded_inner: None,
            inner_random,
            compressed_extensions: vec![],
        })
    }

    pub fn public_key(&self) -> HpkePublicKey {
        HpkePublicKey::from(
            self.config_contents
                .hpke_key_config
                .hpke_public_key
                .clone()
                .into_inner(),
        )
    }

    pub fn encode(&mut self, mut hello: ClientHelloPayload) -> ClientHelloPayload {
        // Swap out the SNI
        if let Some(index) = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::ServerName)
        {
            hello.extensions.remove(index);
        };

        // Remove the ClientExtensions that match outer_exts.
        // Nightly's drain_filter would be nice here.
        let mut indices = Vec::with_capacity(self.compressed_extensions.len());
        for (i, ext) in hello.extensions.iter().enumerate() {
            if self
                .compressed_extensions
                .contains(&ext.get_type())
            {
                indices.push(i);
            }
        }
        let mut outers = Vec::with_capacity(indices.len());
        for index in indices.iter().rev() {
            outers.push(hello.extensions.swap_remove(*index));
        }

        // Add the inner SNI
        hello
            .extensions
            .push(ClientExtension::make_sni(self.hostname.as_ref()));

        // Add these two extensions which can only appear in ClientHelloInner.
        let outer_extensions = EchOuterExtensions(
            outers
                .iter()
                .map(|ext| ext.get_type())
                .collect(),
        );
        hello.extensions.push(outer_extensions);
        hello
            .extensions
            .push(ClientExtension::ClientHelloInnerIndication);

        // Preserve these for reuse
        let original_session_id = hello.session_id;
        let original_random = hello.random;

        // SessionID is required to be empty in the ClientHelloInner.
        hello.session_id = SessionID::empty();

        // The random value must be preserved across HRR for the ClientHelloInner
        hello.random = Random::from(self.inner_random);

        // Create the buffer to be encrypted.
        let mut encoded_hello = Vec::new();
        hello.encode(&mut encoded_hello);
        self.encoded_inner = Some(encoded_hello);

        // Remove the two ClientHelloInner-only extensions.
        hello
            .extensions
            .truncate(hello.extensions.len() - 3);

        // Restore
        hello.session_id = original_session_id;
        hello.random = original_random;
        hello
            .extensions
            .push(ClientExtension::make_sni(
                self.config_contents
                    .public_name
                    .as_ref(),
            ));

        // PSK extensions are prohibited in the ClientHelloOuter.
        let index = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::PreSharedKey);
        if let Some(i) = index {
            hello.extensions.remove(i);
        }

        // Add the extensions that appear compressed in ClientHelloInner.
        hello.extensions.append(&mut outers);

        hello
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::msgs::enums::ExtensionType::ECPointFormats;
    use crate::msgs::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
    use crate::msgs::codec::{Codec, Reader};
    use crate::msgs::enums::ExtensionType::{EllipticCurves, KeyShare};
    use crate::msgs::enums::*;
    use crate::msgs::handshake::*;
    use crate::ProtocolVersion;
    use base64;
    use webpki::DnsNameRef;

    const BASE64_ECHCONFIGS: &str = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";

    fn get_ech_config() -> (EchConfigList, Vec<u8>) {
        // An EchConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
        let bytes = base64::decode(&BASE64_ECHCONFIGS).unwrap();
        let configs = EchConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 1);
        (configs, bytes)
    }

    #[test]
    fn test_echconfig_serialization() {
        let (configs, _bytes) = get_ech_config();
        let config = &configs[0];
        assert_eq!(config.version, EchVersion::V10);
        assert_eq!(
            b"cloudflare-esni.com",
            config
                .contents
                .public_name
                .as_ref()
                .as_ref()
        );
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
        assert_eq!(BASE64_ECHCONFIGS, base64::encode(&output));
    }

    fn get_sample_clienthellopayload() -> ClientHelloPayload {
        let mut random = [0; 32];
        rand::fill_random(&mut random).unwrap();
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from(random),
            session_id: SessionID::random().unwrap(),
            cipher_suites: vec![CipherSuite::TLS_NULL_WITH_NULL_NULL],
            compression_methods: vec![Compression::Null],
            extensions: vec![
                ClientExtension::ECPointFormats(ECPointFormatList::supported()),
                ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
                ClientExtension::make_sni(
                    DnsNameRef::try_from_ascii_str("inner-sni.example.com").unwrap(),
                ),
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

    #[test]
    fn test_encode_client_hello_inner() {
        let ext_vecs = vec![vec![KeyShare, ECPointFormats, EllipticCurves], vec![]];
        for outer_exts in ext_vecs {
            let original_hello = get_sample_clienthellopayload();
            let original_ext_length = original_hello.extensions.len();
            let original_session_id = original_hello.session_id;
            let original_random = original_hello.random.clone();
            let (_configs, bytes) = get_ech_config();
            let dns_name = DnsNameRef::try_from_ascii(b"test.example.com").unwrap();
            let mut ech = Box::new(
                EncryptedClientHello::with_host_and_config_list(dns_name, &bytes).unwrap(),
            );
            ech.compressed_extensions
                .extend_from_slice(outer_exts.as_slice());
            let hello = ech.encode(original_hello);
            assert_eq!(hello.session_id, original_session_id);
            assert_eq!(hello.random, original_random);
            // Return hello should not have a PSK
            assert!(
                hello
                    .find_extension(ExtensionType::PreSharedKey)
                    .is_none()
            );

            let mut reader = Reader::init(&ech.encoded_inner.as_ref().unwrap());
            let decoded = ClientHelloPayload::read(&mut reader).unwrap();
            assert_eq!(decoded.session_id, SessionID::empty());
            assert_ne!(decoded.session_id, original_session_id);
            assert_ne!(decoded.random, original_random);

            // The compressed extensions, plus two for the outer_extensions and ech_is_inner.
            let expected_length = original_ext_length - outer_exts.len() + 2;
            assert_eq!(decoded.extensions.len(), expected_length);
            let decoded_outer = decoded
                .find_extension(ExtensionType::EchOuterExtensions)
                .unwrap();
            let outers = match decoded_outer {
                EchOuterExtensions(outer_exts) => Some(outer_exts),
                _ => None,
            }
            .unwrap();
            assert_eq!(outers.len(), outer_exts.len());
            for ext_type in outers.iter() {
                assert!(outer_exts.contains(ext_type));
            }

            // All of the old extensions except for PSK
            let old_len = original_ext_length - 1;
            assert_eq!(hello.extensions.len(), old_len);
            assert!(
                decoded
                    .find_extension(ExtensionType::PreSharedKey)
                    .is_some()
            );
            assert!(
                decoded
                    .find_extension(ExtensionType::EchIsInner)
                    .is_some()
            );
        }
    }

    #[test]
    fn test_seal() {
        let (ech_list, bytes) = get_ech_config();
        for config in ech_list {
            let dns_name = DnsNameRef::try_from_ascii(b"test.example.com").unwrap();
            for suite in &config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites
            {
                let original_hello = get_sample_clienthellopayload();
                let mut ech = Box::new(
                    EncryptedClientHello::with_host_and_config_list(dns_name, &bytes).unwrap(),
                );
                let outer_exts = vec![KeyShare, ECPointFormats, EllipticCurves];
                ech.compressed_extensions
                    .extend_from_slice(outer_exts.as_slice());
                let mut hello = ech.encode(original_hello);
                let pk_r = ech.public_key();
                let (enc, mut context) = ech
                    .hpke
                    .setup_sender(&pk_r, HPKE_INFO, None, None, None)
                    .unwrap();
                let mut encoded_hello = Vec::new();
                hello.encode(&mut encoded_hello);
                let outer_aad = ClientHelloOuterAAD {
                    cipher_suite: suite.clone(),
                    config_id: config
                        .contents
                        .hpke_key_config
                        .config_id,
                    enc: PayloadU16::new(enc.clone()),
                    outer_hello: PayloadU24::new(encoded_hello),
                };

                let mut aad = Vec::new();
                outer_aad.encode(&mut aad);

                let encoded_inner = ech.encoded_inner.as_ref().unwrap();
                let payload = context
                    .seal(aad.as_slice(), encoded_inner)
                    .unwrap();
                assert!(payload.len() > 0);

                let client_ech = ClientEch {
                    cipher_suite: suite.clone(),
                    config_id: config
                        .contents
                        .hpke_key_config
                        .config_id,
                    enc: PayloadU16::new(enc),
                    payload: PayloadU16::new(payload),
                };

                hello
                    .extensions
                    .push(ClientExtension::EncryptedClientHello(client_ech));
            }
        }
    }
}
