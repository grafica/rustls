use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{CipherSuite, ProtocolVersion};
use crate::msgs::handshake::CertificatePayload;
use crate::msgs::handshake::SessionID;
use crate::SupportedCipherSuite;

use std::cmp;
use std::mem;

// These are the keys and values we store in session storage.

// --- Client types ---
/// Keys for session resumption and tickets.
/// Matching value is a `ClientSessionValue`.
#[derive(Debug)]
pub struct ClientSessionKey {
    kind: &'static [u8],
    dns_name: PayloadU8,
}

impl Codec for ClientSessionKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.kind);
        self.dns_name.encode(bytes);
    }

    // Don't need to read these.
    fn read(_r: &mut Reader) -> Option<ClientSessionKey> {
        None
    }
}

impl ClientSessionKey {
    pub fn session_for_dns_name(dns_name: webpki::DNSNameRef) -> ClientSessionKey {
        let dns_name_str: &str = dns_name.into();
        ClientSessionKey {
            kind: b"session",
            dns_name: PayloadU8::new(dns_name_str.as_bytes().to_vec()),
        }
    }

    pub fn hint_for_dns_name(dns_name: webpki::DNSNameRef) -> ClientSessionKey {
        let dns_name_str: &str = dns_name.into();
        ClientSessionKey {
            kind: b"kx-hint",
            dns_name: PayloadU8::new(dns_name_str.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug)]
pub struct ClientSessionValue {
    pub version: ProtocolVersion,
    pub session_id: SessionID,
    cipher_suite: CipherSuite,
    pub ticket: PayloadU16,
    pub master_secret: PayloadU8,
    pub epoch: u64,
    pub lifetime: u32,
    pub age_add: u32,
    pub extended_ms: bool,
    pub max_early_data_size: u32,
    pub server_cert_chain: CertificatePayload,
}

impl ClientSessionValue {
    pub fn resolve_cipher_suite(
        self,
        enabled_cipher_suites: &[&'static SupportedCipherSuite],
    ) -> Option<ClientSessionValueWithResolvedCipherSuite> {
        let supported_cipher_suite = enabled_cipher_suites
            .iter()
            .find(|scs| scs.suite == self.cipher_suite)?;
        Some(ClientSessionValueWithResolvedCipherSuite {
            value: self,
            supported_cipher_suite,
        })
    }
}

impl Codec for ClientSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.session_id.encode(bytes);
        self.ticket.encode(bytes);
        self.master_secret.encode(bytes);
        self.epoch.encode(bytes);
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        (if self.extended_ms { 1u8 } else { 0u8 }).encode(bytes);
        self.max_early_data_size.encode(bytes);
        self.server_cert_chain.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ClientSessionValue> {
        let v = ProtocolVersion::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let session_id = SessionID::read(r)?;
        let ticket = PayloadU16::read(r)?;
        let ms = PayloadU8::read(r)?;
        let epoch = u64::read(r)?;
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let extended_ms = u8::read(r)?;
        let max_early_data_size = u32::read(r)?;
        let server_cert_chain = CertificatePayload::read(r)?;

        Some(ClientSessionValue {
            version: v,
            cipher_suite,
            session_id,
            ticket,
            master_secret: ms,
            epoch,
            lifetime,
            age_add,
            extended_ms: extended_ms == 1u8,
            max_early_data_size,
            server_cert_chain,
        })
    }
}

#[derive(Debug)]
pub struct ClientSessionValueWithResolvedCipherSuite {
    value: ClientSessionValue,
    supported_cipher_suite: &'static SupportedCipherSuite,
}

impl std::ops::Deref for ClientSessionValueWithResolvedCipherSuite {
    type Target = ClientSessionValue;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

static MAX_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;

impl ClientSessionValueWithResolvedCipherSuite {
    pub fn new(
        v: ProtocolVersion,
        cipher_suite: &'static SupportedCipherSuite,
        session_id: SessionID,
        ticket: Vec<u8>,
        ms: Vec<u8>,
        server_cert_chain: &CertificatePayload,
    ) -> Self {
        ClientSessionValueWithResolvedCipherSuite {
            value: ClientSessionValue {
                version: v,
                cipher_suite: cipher_suite.suite,
                session_id,
                ticket: PayloadU16::new(ticket),
                master_secret: PayloadU8::new(ms),
                epoch: 0,
                lifetime: 0,
                age_add: 0,
                extended_ms: false,
                max_early_data_size: 0,
                server_cert_chain: server_cert_chain.to_owned(),
            },
            supported_cipher_suite: cipher_suite,
        }
    }

    pub fn supported_cipher_suite(&self) -> &'static SupportedCipherSuite {
        self.supported_cipher_suite
    }

    pub fn set_session_id(&mut self, id: SessionID) {
        self.value.session_id = id;
    }

    pub fn set_extended_ms_used(&mut self) {
        self.value.extended_ms = true;
    }

    pub fn set_times(&mut self, receipt_time_secs: u64, lifetime_secs: u32, age_add: u32) {
        self.value.epoch = receipt_time_secs;
        self.value.lifetime = cmp::min(lifetime_secs, MAX_TICKET_LIFETIME);
        self.value.age_add = age_add;
    }

    pub fn has_expired(&self, time_now: u64) -> bool {
        self.value.lifetime != 0 && self.value.epoch + u64::from(self.value.lifetime) < time_now
    }

    pub fn get_obfuscated_ticket_age(&self, time_now: u64) -> u32 {
        let age_secs = time_now.saturating_sub(self.value.epoch);
        let age_millis = age_secs as u32 * 1000;
        age_millis.wrapping_add(self.value.age_add)
    }

    pub fn take_ticket(&mut self) -> Vec<u8> {
        let new_ticket = PayloadU16::new(Vec::new());
        let old_ticket = mem::replace(&mut self.value.ticket, new_ticket);
        old_ticket.0
    }

    pub fn set_max_early_data_size(&mut self, sz: u32) {
        self.value.max_early_data_size = sz;
    }
}

// --- Server types ---
pub type ServerSessionKey = SessionID;

#[derive(Debug)]
pub struct ServerSessionValue {
    pub sni: Option<webpki::DNSName>,
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub master_secret: PayloadU8,
    pub extended_ms: bool,
    pub client_cert_chain: Option<CertificatePayload>,
    pub alpn: Option<PayloadU8>,
    pub application_data: PayloadU16,
}

impl Codec for ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let Some(ref sni) = self.sni {
            1u8.encode(bytes);
            let sni_bytes: &str = sni.as_ref().into();
            PayloadU8::new(Vec::from(sni_bytes)).encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.master_secret.encode(bytes);
        (if self.extended_ms { 1u8 } else { 0u8 }).encode(bytes);
        if let Some(ref chain) = self.client_cert_chain {
            1u8.encode(bytes);
            chain.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        if let Some(ref alpn) = self.alpn {
            1u8.encode(bytes);
            alpn.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.application_data.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ServerSessionValue> {
        let has_sni = u8::read(r)?;
        let sni = if has_sni == 1 {
            let dns_name = PayloadU8::read(r)?;
            let dns_name = webpki::DNSNameRef::try_from_ascii(&dns_name.0).ok()?;
            Some(dns_name.into())
        } else {
            None
        };
        let v = ProtocolVersion::read(r)?;
        let cs = CipherSuite::read(r)?;
        let ms = PayloadU8::read(r)?;
        let ems = u8::read(r)?;
        let has_ccert = u8::read(r)? == 1;
        let ccert = if has_ccert {
            Some(CertificatePayload::read(r)?)
        } else {
            None
        };
        let has_alpn = u8::read(r)? == 1;
        let alpn = if has_alpn {
            Some(PayloadU8::read(r)?)
        } else {
            None
        };
        let application_data = PayloadU16::read(r)?;

        Some(ServerSessionValue {
            sni,
            version: v,
            cipher_suite: cs,
            master_secret: ms,
            extended_ms: ems == 1u8,
            client_cert_chain: ccert,
            alpn,
            application_data,
        })
    }
}

impl ServerSessionValue {
    pub fn new(
        sni: Option<&webpki::DNSName>,
        v: ProtocolVersion,
        cs: CipherSuite,
        ms: Vec<u8>,
        cert_chain: &Option<CertificatePayload>,
        alpn: Option<Vec<u8>>,
        application_data: Vec<u8>,
    ) -> ServerSessionValue {
        ServerSessionValue {
            sni: sni.cloned(),
            version: v,
            cipher_suite: cs,
            master_secret: PayloadU8::new(ms),
            extended_ms: false,
            client_cert_chain: cert_chain.clone(),
            alpn: alpn.map(PayloadU8::new),
            application_data: PayloadU16::new(application_data),
        }
    }

    pub fn set_extended_ms_used(&mut self) {
        self.extended_ms = true;
    }
}
