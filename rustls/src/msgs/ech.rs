use crate::conn::ConnectionRandoms;
use crate::hash_hs::HandshakeHash;
use crate::key_schedule::hkdf_expand;
use crate::msgs::base::{PayloadU16, PayloadU24};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{ExtensionType, HandshakeType};
use crate::msgs::handshake::ClientExtension::EchOuterExtensions;
use crate::msgs::handshake::{
    ClientEch, ClientExtension, ClientHelloOuterAAD, ClientHelloPayload, EchConfig,
    EchConfigContents, EchConfigList, HandshakeMessagePayload, HandshakePayload,
    HpkeSymmetricCipherSuite, Random, ServerHelloPayload, SessionID,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::rand;
use crate::{Error, KeyLog, ProtocolVersion};
use ring::hkdf::Prk;
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use webpki;

const HPKE_INFO: &[u8; 8] = b"tls ech\0";

fn hpke_info(config: &EchConfig) -> Vec<u8> {
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(HPKE_INFO);
    config.encode(&mut info);
    info
}

pub struct EncryptedClientHello {
    pub hostname: webpki::DnsName,
    pub hpke: Hpke,
    pub hpke_info: Vec<u8>,
    pub suite: HpkeSymmetricCipherSuite,
    pub config_contents: EchConfigContents,
    pub inner_message: Option<Message>,
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
                let c = &config.contents;
                Some((
                    c.clone(),
                    hpke_info(&config),
                    c.hpke_key_config
                        .hpke_symmetric_cipher_suites
                        .iter()
                        .find_map(|suite| {
                            Some((
                                suite,
                                hpke_rs::Hpke::new(
                                    Mode::Base,
                                    HpkeKemMode::try_from(c.hpke_key_config.hpke_kem_id.get_u16())
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
        rand::fill_random(&mut inner_random).unwrap();

        Ok(EncryptedClientHello {
            hostname: name.to_owned(),
            hpke,
            hpke_info,
            suite: suite.clone(),
            config_contents,
            inner_message: None,
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

    pub fn encode(&mut self, mut hello: ClientHelloPayload) -> HandshakeMessagePayload {
        // Remove the SNI
        if let Some(index) = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::ServerName)
        {
            hello.extensions.remove(index);
        };

        let mut inner_hello = hello.clone();

        // Remove the ClientExtensions that match outer_exts.
        // Nightly's drain_filter would be nice here.
        let mut indices = Vec::with_capacity(self.compressed_extensions.len());
        for (i, ext) in inner_hello
            .extensions
            .iter()
            .enumerate()
        {
            if self
                .compressed_extensions
                .contains(&ext.get_type())
            {
                indices.push(i);
            }
        }
        let mut outers = Vec::with_capacity(indices.len());
        for index in indices.iter().rev() {
            outers.push(
                inner_hello
                    .extensions
                    .swap_remove(*index),
            );
        }


        // Add the inner SNI
        inner_hello
            .extensions
            .insert(0, ClientExtension::make_sni(self.hostname.as_ref()));
        inner_hello
            .extensions
            .insert(0, ClientExtension::ClientHelloInnerIndication);

        // Preserve these for reuse
        let original_session_id = inner_hello.session_id;
        inner_hello.random = Random::from(self.inner_random);

        // SessionID is required to be empty in the EncodedClientHelloInner.
        inner_hello.session_id = SessionID::empty();

        // Add these two extensions which can only appear in ClientHelloInner.
        let outer_extensions = EchOuterExtensions(
            outers
                .iter()
                .map(|ext| ext.get_type())
                .collect(),
        );
        inner_hello
            .extensions
            .push(outer_extensions);

        // Create the buffer to be encrypted.
        let mut encoded_hello = Vec::new();
        inner_hello.encode(&mut encoded_hello);
        println!("encoded hello bytes: {:?}", encoded_hello);
        inner_hello.session_id = original_session_id;

        // Remove outer_extensions.
        inner_hello.extensions.pop();
        inner_hello.extensions.extend(outers);

        let chp = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(inner_hello),
        };
        self.inner_message = Some(Message {
            // "This value MUST be set to 0x0303 for all records generated
            //  by a TLS 1.3 implementation other than an initial ClientHello
            //  (i.e., one not generated after a HelloRetryRequest)"
            version: ProtocolVersion::TLSv1_0,
            payload: MessagePayload::Handshake(chp),
        });

        // Add the outer SNI
        hello.extensions.insert(
            0,
            ClientExtension::make_sni(
                self.config_contents
                    .public_name
                    .as_ref(),
            ),
        );

        // PSK extensions are prohibited in the ClientHelloOuter.
        let index = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::PreSharedKey);
        if let Some(i) = index {
            hello.extensions.remove(i);
        }

        let pk_r = self.public_key();
        let (enc, mut context) = self
            .hpke
            .setup_sender(&pk_r, self.hpke_info.as_slice(), None, None, None)
            .unwrap();
        let mut encoded_outer = Vec::new();
        hello.encode(&mut encoded_outer);
        let outer_aad = ClientHelloOuterAAD {
            cipher_suite: self.suite.clone(),
            config_id: self
                .config_contents
                .hpke_key_config
                .config_id,
            enc: PayloadU16::new(enc.clone()),
            outer_hello: PayloadU24::new(encoded_outer),
        };

        let mut aad = Vec::new();
        outer_aad.encode(&mut aad);

        let payload = context
            .seal(aad.as_slice(), &*encoded_hello)
            .unwrap();
        let client_ech = ClientEch {
            cipher_suite: self.suite.clone(),
            config_id: self
                .config_contents
                .hpke_key_config
                .config_id,
            enc: PayloadU16::new(enc),
            payload: PayloadU16::new(payload),
        };

        hello
            .extensions
            .insert(0, ClientExtension::EncryptedClientHello(client_ech));
        //.push();
        //hello_details
        //    .sent_extensions
        //   .push(ExtensionType::EncryptedClientHello);
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(hello),
        }
    }

    pub(crate) fn confirm_ech(
        &self,
        server_hello: &ServerHelloPayload,
        randoms: &ConnectionRandoms,
        alg: &'static ring::digest::Algorithm,
    ) -> (ConnectionRandoms, HandshakeHash) {
        let message = self.inner_message.as_ref().unwrap();
        let mut confirmation_transcript = HandshakeHash::new();
        confirmation_transcript.start_hash(alg);
        confirmation_transcript.add_message(message);
        let mut encoded_sh = Vec::new();
        server_hello.encode_for_ech_confirmation(&mut encoded_sh);
        confirmation_transcript.update_raw(&mut encoded_sh);
        let key = hkdf_expand(
            Prk::new_less_safe(, ),
            alg,
            b"ech accept confirmation",
            &confirmation_transcript.get_current_hash().as_ref(),
        );
        println!("key: {:?}", key);
        // TODO: Actually confirm

        let mut inner_transcript = HandshakeHash::new();
        inner_transcript.start_hash(alg);
        inner_transcript.add_message(message);
        let inner_randoms = ConnectionRandoms {
            we_are_client: true,
            client: self.inner_random,
            server: randoms.server,
        };

        println!("returning inner_transcript");
        (inner_randoms, inner_transcript)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::msgs::enums::ExtensionType::ECPointFormats;
    use crate::internal::msgs::handshake::HandshakePayload::ClientHello;
    use crate::msgs::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
    use crate::msgs::codec::{Codec, Reader};
    use crate::msgs::enums::ExtensionType::{EllipticCurves, KeyShare};
    use crate::msgs::enums::*;
    use crate::msgs::handshake::*;
    use crate::ProtocolVersion;
    use base64;
    use std::convert::TryInto;
    use webpki::DnsNameRef;

    const BASE64_ECHCONFIGS: &str = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
    fn get_ech_config(s: &str) -> (EchConfigList, Vec<u8>) {
        // An EchConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
        let bytes = base64::decode(s).unwrap();
        let configs = EchConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 1);
        (configs, bytes.to_vec())
    }

    #[test]
    fn test_echconfig_serialization() {
        let (configs, _bytes) = get_ech_config(BASE64_ECHCONFIGS);
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
            let (_configs, bytes) = get_ech_config(BASE64_ECHCONFIGS);
            let dns_name = DnsNameRef::try_from_ascii(b"test.example.com").unwrap();
            let mut ech = Box::new(
                EncryptedClientHello::with_host_and_config_list(dns_name, &bytes).unwrap(),
            );
            ech.compressed_extensions
                .extend_from_slice(outer_exts.as_slice());
            let hmp = ech.encode(original_hello);
            let hello: ClientHelloPayload = match hmp.payload {
                ClientHello(chp) => chp,
                _ => unreachable!(),
            };
            assert_eq!(hello.session_id, original_session_id);
            assert_eq!(hello.random, original_random);
            // Return hello should not have a PSK
            assert!(
                hello
                    .find_extension(ExtensionType::PreSharedKey)
                    .is_none()
            );

            /*
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
            );*/
        }
    }

    #[test]
    fn test_seal() {
        let (ech_list, bytes) = get_ech_config(BASE64_ECHCONFIGS);
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

                /*
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

                 */
            }
        }
    }

    #[test]
    fn test_hello_encoding() {
        let ech_config_list = "AEj+CgBEAQAgACDQmv0Ys9bmdUDb0kfmFUwNIasNbyzbFu9RYmWNVJ+iAQAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
        let hello_base: Vec<u8> = vec![
            1, 0, 1, 4, 3, 3, 241, 156, 177, 227, 148, 237, 84, 44, 11, 125, 121, 67, 174, 166,
            117, 222, 27, 146, 204, 201, 165, 206, 117, 25, 95, 131, 247, 69, 30, 164, 203, 82, 32,
            98, 9, 215, 90, 54, 11, 222, 185, 45, 118, 15, 211, 164, 37, 244, 17, 211, 109, 133,
            204, 175, 230, 224, 52, 122, 2, 138, 152, 211, 152, 85, 179, 0, 38, 192, 47, 192, 48,
            192, 43, 192, 44, 204, 168, 204, 169, 192, 19, 192, 9, 192, 20, 192, 10, 0, 156, 0,
            157, 0, 47, 0, 53, 192, 18, 0, 10, 19, 1, 19, 3, 19, 2, 1, 0, 0, 149, 0, 0, 0, 26, 0,
            24, 0, 0, 21, 99, 114, 121, 112, 116, 111, 46, 99, 108, 111, 117, 100, 102, 108, 97,
            114, 101, 46, 99, 111, 109, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 10, 0, 10, 0, 8, 0, 29, 0,
            23, 0, 24, 0, 25, 0, 11, 0, 2, 1, 0, 0, 13, 0, 28, 0, 26, 8, 4, 4, 3, 8, 7, 8, 5, 8, 6,
            4, 1, 5, 1, 6, 1, 5, 3, 6, 3, 2, 1, 2, 3, 254, 97, 255, 1, 0, 1, 0, 0, 18, 0, 0, 0, 43,
            0, 3, 2, 3, 4, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 53, 98, 122, 180, 33, 196, 73, 33,
            36, 164, 34, 201, 26, 121, 93, 59, 196, 17, 66, 149, 47, 254, 90, 55, 85, 88, 170, 134,
            204, 173, 130, 111,
        ];
        let hello_outer: Vec<u8> = vec![
            1, 0, 2, 10, 3, 3, 241, 156, 177, 227, 148, 237, 84, 44, 11, 125, 121, 67, 174, 166,
            117, 222, 27, 146, 204, 201, 165, 206, 117, 25, 95, 131, 247, 69, 30, 164, 203, 82, 32,
            98, 9, 215, 90, 54, 11, 222, 185, 45, 118, 15, 211, 164, 37, 244, 17, 211, 109, 133,
            204, 175, 230, 224, 52, 122, 2, 138, 152, 211, 152, 85, 179, 0, 38, 192, 47, 192, 48,
            192, 43, 192, 44, 204, 168, 204, 169, 192, 19, 192, 9, 192, 20, 192, 10, 0, 156, 0,
            157, 0, 47, 0, 53, 192, 18, 0, 10, 19, 1, 19, 3, 19, 2, 1, 0, 1, 155, 254, 10, 0, 254,
            0, 1, 0, 1, 1, 0, 32, 148, 165, 229, 109, 94, 130, 11, 15, 234, 203, 87, 82, 105, 168,
            75, 243, 126, 196, 12, 32, 124, 215, 51, 86, 232, 214, 206, 158, 108, 68, 228, 96, 0,
            213, 202, 83, 245, 186, 226, 201, 100, 65, 225, 18, 5, 5, 153, 114, 203, 121, 231, 36,
            217, 188, 161, 22, 58, 37, 2, 54, 127, 179, 249, 210, 169, 115, 138, 248, 242, 89, 37,
            8, 82, 253, 84, 41, 18, 17, 143, 5, 149, 41, 254, 46, 249, 167, 230, 162, 113, 6, 172,
            7, 183, 125, 23, 90, 75, 68, 226, 89, 149, 158, 142, 169, 173, 63, 24, 122, 244, 124,
            36, 171, 196, 84, 43, 144, 99, 164, 224, 148, 41, 74, 98, 103, 237, 163, 182, 14, 65,
            89, 242, 216, 131, 105, 15, 174, 115, 59, 109, 113, 54, 72, 166, 182, 80, 63, 242, 156,
            32, 19, 33, 219, 80, 90, 172, 6, 208, 140, 234, 157, 89, 85, 54, 35, 107, 234, 197, 18,
            77, 193, 128, 236, 91, 71, 141, 39, 249, 32, 166, 137, 116, 210, 85, 59, 6, 51, 30, 97,
            140, 23, 181, 252, 191, 196, 254, 31, 175, 251, 35, 183, 236, 25, 233, 39, 245, 115,
            62, 78, 83, 197, 183, 122, 163, 117, 120, 192, 36, 95, 31, 69, 228, 101, 247, 26, 244,
            148, 106, 126, 213, 85, 173, 216, 111, 107, 187, 179, 243, 198, 90, 111, 7, 219, 102,
            57, 94, 23, 20, 0, 0, 0, 24, 0, 22, 0, 0, 19, 99, 108, 111, 117, 100, 102, 108, 97,
            114, 101, 45, 101, 115, 110, 105, 46, 99, 111, 109, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 10,
            0, 10, 0, 8, 0, 29, 0, 23, 0, 24, 0, 25, 0, 11, 0, 2, 1, 0, 0, 13, 0, 28, 0, 26, 8, 4,
            4, 3, 8, 7, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 5, 3, 6, 3, 2, 1, 2, 3, 254, 97, 255, 1, 0,
            1, 0, 0, 18, 0, 0, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 51, 0, 38, 0, 36, 0, 29,
            0, 32, 53, 98, 122, 180, 33, 196, 73, 33, 36, 164, 34, 201, 26, 121, 93, 59, 196, 17,
            66, 149, 47, 254, 90, 55, 85, 88, 170, 134, 204, 173, 130, 111,
        ];
        let hello_inner: Vec<u8> = vec![
            1, 0, 1, 8, 3, 3, 249, 151, 214, 12, 175, 208, 239, 159, 52, 62, 98, 149, 86, 99, 138,
            200, 48, 254, 9, 194, 223, 234, 59, 234, 110, 150, 223, 87, 193, 238, 134, 216, 32, 98,
            9, 215, 90, 54, 11, 222, 185, 45, 118, 15, 211, 164, 37, 244, 17, 211, 109, 133, 204,
            175, 230, 224, 52, 122, 2, 138, 152, 211, 152, 85, 179, 0, 38, 192, 47, 192, 48, 192,
            43, 192, 44, 204, 168, 204, 169, 192, 19, 192, 9, 192, 20, 192, 10, 0, 156, 0, 157, 0,
            47, 0, 53, 192, 18, 0, 10, 19, 1, 19, 3, 19, 2, 1, 0, 0, 153, 218, 9, 0, 0, 0, 0, 0,
            26, 0, 24, 0, 0, 21, 99, 114, 121, 112, 116, 111, 46, 99, 108, 111, 117, 100, 102, 108,
            97, 114, 101, 46, 99, 111, 109, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 10, 0, 10, 0, 8, 0, 29,
            0, 23, 0, 24, 0, 25, 0, 11, 0, 2, 1, 0, 0, 13, 0, 28, 0, 26, 8, 4, 4, 3, 8, 7, 8, 5, 8,
            6, 4, 1, 5, 1, 6, 1, 5, 3, 6, 3, 2, 1, 2, 3, 254, 97, 255, 1, 0, 1, 0, 0, 18, 0, 0, 0,
            43, 0, 3, 2, 3, 4, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 53, 98, 122, 180, 33, 196, 73,
            33, 36, 164, 34, 201, 26, 121, 93, 59, 196, 17, 66, 149, 47, 254, 90, 55, 85, 88, 170,
            134, 204, 173, 130, 111,
        ];

        /*
        for vec in &[hello_base, hello_outer, hello_inner] {
            let deserialized =
                HandshakeMessagePayload::read(&mut Reader::init(vec.as_slice())).unwrap();
            let mut serialized: Vec<u8> = Vec::new();
            deserialized.encode(&mut serialized);
            assert_eq!(*vec, serialized);
        } */


        let (_ech_configs, bytes) = get_ech_config(ech_config_list);
        let host = webpki::DnsNameRef::try_from_ascii(b"crypto.cloudflare.com").unwrap();
        let mut ech = EncryptedClientHello::with_host_and_config_list(host, &bytes).unwrap();
        let base = HandshakeMessagePayload::read(&mut Reader::init(hello_base.as_slice())).unwrap();
        let expected_inner =
            HandshakeMessagePayload::read(&mut Reader::init(hello_inner.as_slice())).unwrap();
        let expected_outer =
            HandshakeMessagePayload::read(&mut Reader::init(hello_outer.as_slice())).unwrap();

        let payload = match base.payload {
            ClientHello(chp) => chp,
            _ => unreachable!(),
        };

        let inner_payload = match expected_inner.payload {
            ClientHello(ref chp) => chp,
            _ => unreachable!(),
        };

        let mut test_random = [0u8; 32];
        inner_payload
            .random
            .write_slice(&mut test_random);
        ech.inner_random = test_random;
        ech.compressed_extensions = vec![KeyShare];
        let outer = ech.encode(payload);
        let inner = ech.inner_message.unwrap();
        let inner_payload = match inner.payload {
            MessagePayload::Handshake(hmp) => hmp,
            _ => unreachable!(),
        };


        println!("expected:       {:?}", expected_inner);
        println!("got inner:      {:?}", inner_payload);
        let mut serialized_inner: Vec<u8> = Vec::new();
        inner_payload.encode(&mut serialized_inner);
        assert_eq!(hello_inner, serialized_inner);

        println!("expected:       {:?}", expected_outer);
        println!("got outer:      {:?}", outer);

        let mut serialized_outer: Vec<u8> = Vec::new();
        assert_eq!(outer.typ, expected_outer.typ);

        let outer_payload = match expected_outer.payload {
            ClientHello(ref chp) => chp,
            _ => unreachable!(),
        };

        let expected_payload = match expected_outer.payload {
            ClientHello(ref chp) => chp,
            _ => unreachable!(),
        };

        assert_eq!(
            expected_payload.client_version,
            outer_payload.client_version
        );
        assert_eq!(expected_payload.random, outer_payload.random);
        assert_eq!(expected_payload.session_id, outer_payload.session_id);
        assert_eq!(expected_payload.cipher_suites, outer_payload.cipher_suites);
        assert_eq!(
            expected_payload.compression_methods,
            outer_payload.compression_methods
        );
    }
}
