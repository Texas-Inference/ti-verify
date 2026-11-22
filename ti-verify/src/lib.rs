//! `ti-verify`: check that a host's TLS key lives in an attested TDX VM running a
//! published release (spec sections 1, 4, 7.1 M9).
//!
//! The attestation request travels on the same TLS connection whose server key we
//! record: one socket, full handshake (no resumption, no early data), ALPN http/1.1
//! only, `Connection: close`, no redirects.

use base64::Engine;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use ti_tdx::backend::QuoteBackend;
use ti_tdx::binding::{parse_key_hash, parse_nonce, spki_hash, NONCE_LEN};
use ti_tdx::policy::{decide, Inputs, Pass};
use ti_tdx::reason::{Fail, Reason};
use ti_tdx::release::ReleaseRecord;

pub const ATTEST_PATH: &str = "/.well-known/ti-attestation";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer {
    pub version: String,
    pub nonce: String,
    pub key_hashes: Vec<String>,
    pub quote: String,
    pub ccel: String,
    pub provider: String,
    pub image_version: String,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    /// Accepts `https://host`, `https://host:port` or `host[:port]`. Nothing else.
    pub fn parse(s: &str) -> Result<Target, Fail> {
        let rest = s.strip_prefix("https://").unwrap_or(s);
        let rest = rest.trim_end_matches('/');
        if rest.contains('/') || rest.contains('@') || rest.is_empty() {
            return Err(Fail::new(Reason::Tls, format!("bad target {s:?}")));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse().map_err(|_| Fail::new(Reason::Tls, "bad port"))?,
            ),
            None => (rest, 443),
        };
        Ok(Target {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Root store: the public web PKI by default, or the given PEM roots instead.
pub fn roots(extra_pem: Option<&[u8]>) -> Result<RootCertStore, Fail> {
    let mut store = RootCertStore::empty();
    match extra_pem {
        None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Some(pem) => {
            for c in rustls_pemfile::certs(&mut &pem[..]) {
                let c = c.map_err(|e| Fail::new(Reason::Tls, format!("bad CA file: {e}")))?;
                store
                    .add(c)
                    .map_err(|e| Fail::new(Reason::Tls, format!("bad CA: {e}")))?;
            }
        }
    }
    Ok(store)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The verifying connection's TLS settings (spec M9).
pub fn attest_client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_early_data = false;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

pub fn leaf_key_hash(cert: &CertificateDer) -> Result<[u8; 32], Fail> {
    let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| Fail::new(Reason::Tls, format!("bad server certificate: {e}")))?;
    Ok(spki_hash(c.tbs_certificate.subject_pki.raw))
}

#[derive(Debug, Clone)]
pub struct Fetched {
    pub connection_key: [u8; 32],
    pub answer: Answer,
}

pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).expect("os randomness");
    n
}

/// One connection: handshake, record the server key, ask for the attestation on it.
pub fn fetch(
    target: &Target,
    cfg: Arc<ClientConfig>,
    nonce: &[u8; NONCE_LEN],
) -> Result<Fetched, Fail> {
    let name = ServerName::try_from(target.host.clone())
        .map_err(|_| Fail::new(Reason::Tls, "bad host name"))?;
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|e| Fail::new(Reason::Tls, format!("connect: {e}")))?;
    tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let conn =
        ClientConnection::new(cfg, name).map_err(|e| Fail::new(Reason::Tls, e.to_string()))?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn
            .complete_io(&mut s.sock)
            .map_err(|e| Fail::new(Reason::Tls, format!("handshake: {e}")))?;
    }
    let certs = s
        .conn
        .peer_certificates()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| Fail::new(Reason::Tls, "server presented no certificate"))?;
    let connection_key = leaf_key_hash(&certs[0])?;
    if s.conn.alpn_protocol().is_some_and(|p| p != b"http/1.1") {
        return Err(Fail::new(
            Reason::Tls,
            "server negotiated a protocol other than http/1.1",
        ));
    }
    let req = format!(
        "GET {ATTEST_PATH}?nonce={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ti-verify/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        hex::encode(nonce),
        target.host
    );
    s.write_all(req.as_bytes())
        .map_err(|e| Fail::new(Reason::Http, format!("write: {e}")))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err(Fail::new(Reason::Http, "response too large"));
                }
            }
            // A peer that closes without close_notify after a complete response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Fail::new(Reason::Http, format!("read: {e}"))),
        }
    }
    let body = parse_http(&raw)?;
    let answer: Answer = serde_json::from_slice(&body)
        .map_err(|e| Fail::new(Reason::Http, format!("bad JSON: {e}")))?;
    Ok(Fetched {
        connection_key,
        answer,
    })
}

/// Minimal HTTP/1.1 response parsing: status 200 only, Content-Length or chunked.
pub fn parse_http(raw: &[u8]) -> Result<Vec<u8>, Fail> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Fail::new(Reason::Http, "no header terminator"))?;
    let head = std::str::from_utf8(&raw[..end])
        .map_err(|_| Fail::new(Reason::Http, "non-UTF-8 headers"))?;
    let body = &raw[end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(Fail::new(Reason::Http, format!("status {status:?}")));
    }
    let mut len: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                len = Some(
                    v.parse()
                        .map_err(|_| Fail::new(Reason::Http, "bad content-length"))?,
                );
            } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    if chunked {
        return dechunk(body);
    }
    match len {
        Some(n) if body.len() >= n => Ok(body[..n].to_vec()),
        Some(_) => Err(Fail::new(Reason::Http, "truncated body")),
        None => Ok(body.to_vec()),
    }
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, Fail> {
    let mut out = Vec::new();
    loop {
        let nl = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| Fail::new(Reason::Http, "bad chunk"))?;
        let size_s =
            std::str::from_utf8(&b[..nl]).map_err(|_| Fail::new(Reason::Http, "bad chunk"))?;
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| Fail::new(Reason::Http, "bad chunk size"))?;
        b = &b[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_RESPONSE {
            return Err(Fail::new(Reason::Http, "chunk too large"));
        }
        let need = size
            .checked_add(2)
            .ok_or_else(|| Fail::new(Reason::Http, "chunk size overflow"))?;
        if b.len() < need {
            return Err(Fail::new(Reason::Http, "truncated chunk"));
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
        if out.len() > MAX_RESPONSE {
            return Err(Fail::new(Reason::Http, "response too large"));
        }
    }
}

#[derive(Debug)]
pub struct Checked {
    pub pass: Pass,
    pub key_hash: [u8; 32],
    pub image_version: String,
    /// The time the quote and release record were checked at: stored as `verified_at`.
    pub at: u64,
}

/// Every check after the fetch, in the order the reasons are defined.
pub fn check(
    target: &Target,
    nonce: &[u8; NONCE_LEN],
    fetched: &Fetched,
    backend: &dyn QuoteBackend,
    records: &[ReleaseRecord],
    now: u64,
    production: bool,
) -> Result<Checked, Fail> {
    let a = &fetched.answer;
    if a.version != "ti-attest-v1" {
        return Err(Fail::new(
            Reason::Http,
            format!("unknown answer version {:?}", a.version),
        ));
    }
    if parse_nonce(&a.nonce).as_ref() != Some(nonce) {
        return Err(Fail::new(
            Reason::NonceMismatch,
            "answer does not echo our nonce",
        ));
    }
    let mut keys = Vec::new();
    for k in &a.key_hashes {
        keys.push(parse_key_hash(k).ok_or_else(|| Fail::new(Reason::Http, "bad key hash"))?);
    }
    if !keys.contains(&fetched.connection_key) {
        return Err(Fail::new(
            Reason::KeyNotBound,
            format!(
                "connection key {} not in the attested list",
                hex::encode(fetched.connection_key)
            ),
        ));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let quote = b64
        .decode(&a.quote)
        .map_err(|_| Fail::new(Reason::QuoteSignature, "quote is not base64"))?;
    let ccel = b64
        .decode(&a.ccel)
        .map_err(|_| Fail::new(Reason::EventLog, "event log is not base64"))?;
    let verified = backend.verify(&quote, now)?;
    let pass = decide(&Inputs {
        host: &target.host,
        now,
        nonce,
        listed_keys: &keys,
        connection_key: &fetched.connection_key,
        quote: &verified,
        ccel: &ccel,
        records,
        production,
    })?;
    Ok(Checked {
        pass,
        key_hash: fetched.connection_key,
        image_version: a.image_version.clone(),
        at: now,
    })
}

/// A client config that accepts only the verified key (spec M9): every later
/// connection must present the same SubjectPublicKeyInfo, on top of normal PKI checks.
pub fn pinned_client_config(roots: RootCertStore, key_hash: [u8; 32]) -> Arc<ClientConfig> {
    let inner =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .expect("verifier");
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { inner, key_hash }))
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_early_data = false;
    Arc::new(cfg)
}

#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    key_hash: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ok =
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        let h = leaf_key_hash(end_entity).map_err(|e| rustls::Error::General(e.to_string()))?;
        if h != self.key_hash {
            return Err(rustls::Error::General(
                "server key is not the attested key".into(),
            ));
        }
        Ok(ok)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// For a reference boot (spec D7): verify the signature, nonce and key binding, then
/// return the measurements a release record needs. No release record is consulted.
pub fn inspect(
    nonce: &[u8; NONCE_LEN],
    fetched: &Fetched,
    backend: &dyn QuoteBackend,
    now: u64,
) -> Result<serde_json::Value, Fail> {
    let a = &fetched.answer;
    if parse_nonce(&a.nonce).as_ref() != Some(nonce) {
        return Err(Fail::new(
            Reason::NonceMismatch,
            "answer does not echo our nonce",
        ));
    }
    let keys: Vec<[u8; 32]> = a
        .key_hashes
        .iter()
        .filter_map(|k| parse_key_hash(k))
        .collect();
    if !keys.contains(&fetched.connection_key) {
        return Err(Fail::new(
            Reason::KeyNotBound,
            "connection key not in the attested list",
        ));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let quote = b64
        .decode(&a.quote)
        .map_err(|_| Fail::new(Reason::QuoteSignature, "quote is not base64"))?;
    let ccel = b64
        .decode(&a.ccel)
        .map_err(|_| Fail::new(Reason::EventLog, "event log is not base64"))?;
    let v = backend.verify(&quote, now)?;
    if v.report.report_data != ti_tdx::binding::report_data(nonce, &keys) {
        return Err(Fail::new(
            Reason::BindingMismatch,
            "report data does not bind this nonce and key list",
        ));
    }
    let log = ti_tdx::ccel::parse(&ccel).map_err(|e| Fail::new(Reason::EventLog, e))?;
    let replay = log.replay().map_err(|e| Fail::new(Reason::EventLog, e))?;
    let r = &v.report;
    Ok(serde_json::json!({
        "tcb_status": v.tcb_status,
        "advisory_ids": v.advisory_ids,
        "mrtd": hex::encode(r.mr_td),
        "rtmr0": hex::encode(r.rtmr[0]),
        "rtmr1": hex::encode(r.rtmr[1]),
        "rtmr2": hex::encode(r.rtmr[2]),
        "rtmr3": hex::encode(r.rtmr[3]),
        "replay_matches_quote": replay[..3] == r.rtmr[..3],
        "xfam": hex::encode(r.xfam),
        "td_attributes": hex::encode(r.td_attributes),
        "mr_seam": hex::encode(r.mr_seam),
        "mr_signer_seam": hex::encode(r.mr_signer_seam),
        "mr_config_id": hex::encode(r.mr_config_id),
        "mr_owner": hex::encode(r.mr_owner),
        "mr_owner_config": hex::encode(r.mr_owner_config),
        "boot_applications_rtmr1": log.boot_app_digests().iter().map(hex::encode).collect::<Vec<_>>(),
        // Spec 13.2 item 2: the record's min_tcb_eval_data_number is the lower of these two,
        // read from Intel PCS's standard collateral on the day of recording.
        "tcb_eval_data_number": v.tcb_eval_data_number,
        "qe_tcb_eval_data_number": v.qe_tcb_eval_data_number,
        "secure_boot": secure_boot_json(&log),
        "events": log.describe(),
        "image_version": a.image_version,
    }))
}

fn secure_boot_json(log: &ti_tdx::ccel::Log) -> serde_json::Value {
    match log.secure_boot_config() {
        Ok(c) => {
            let list = |l: &Option<Vec<ti_tdx::ccel::SigEntry>>| -> serde_json::Value {
                match l {
                    None => serde_json::Value::Null,
                    Some(v) => v
                        .iter()
                        .map(|e| match e {
                            Ok(d) => format!("x509 sha256 {}", hex::encode(d)),
                            Err(t) => format!("other type {}", hex::encode(t)),
                        })
                        .collect(),
                }
            };
            serde_json::json!({"secure_boot": c.secure_boot, "pk": list(&c.pk), "kek": list(&c.kek), "db": list(&c.db)})
        }
        Err(e) => serde_json::json!({"error": e}),
    }
}

/// Spec 13.6: replay a reference boot's event log offline (a worker has no shell, so its CCEL
/// arrives as a file). Prints the replayed RTMR0 to RTMR2, the Secure Boot variables and the
/// boot applications. The caller compares the registers with the record and the manifest.
pub fn replay_event_log(ccel: &[u8]) -> Result<serde_json::Value, Fail> {
    let log = ti_tdx::ccel::parse(ccel).map_err(|e| Fail::new(Reason::EventLog, e))?;
    let replay = log.replay().map_err(|e| Fail::new(Reason::EventLog, e))?;
    Ok(serde_json::json!({
        "rtmr0": hex::encode(replay[0]),
        "rtmr1": hex::encode(replay[1]),
        "rtmr2": hex::encode(replay[2]),
        "boot_applications_rtmr1": log.boot_app_digests().iter().map(hex::encode).collect::<Vec<_>>(),
        "secure_boot": secure_boot_json(&log),
    }))
}

/// Fetch and check a live host with the production backend. Collateral comes from the
/// given cache or from Intel's Provisioning Certification Service.
pub fn verify_live(
    target: &Target,
    records: &[ReleaseRecord],
    ca_pem: Option<&[u8]>,
    collateral: Option<ti_tdx::backend::Collateral>,
    now: u64,
    production: bool,
) -> Result<(Checked, Fetched, ti_tdx::backend::Collateral), Fail> {
    let cfg = attest_client_config(roots(ca_pem)?);
    let nonce = new_nonce();
    let fetched = fetch(target, cfg, &nonce)?;
    let collateral = match collateral {
        Some(c) => c,
        None => {
            let quote = base64::engine::general_purpose::STANDARD
                .decode(&fetched.answer.quote)
                .map_err(|_| Fail::new(Reason::QuoteSignature, "quote is not base64"))?;
            if !ti_tdx::backend::is_tdx_quote(&quote) {
                return Err(Fail::new(Reason::QuoteSignature, "not a TDX quote"));
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?;
            rt.block_on(async {
                dcap_qvl::collateral::CollateralClient::with_default_http(
                    dcap_qvl::collateral::INTEL_PCS_URL,
                )?
                .fetch(&quote)
                .await
            })
            .map_err(|e| Fail::new(Reason::Collateral, format!("Intel PCS: {e:#}")))?
        }
    };
    let backend = ti_tdx::backend::DcapBackend { collateral };
    let checked = check(target, &nonce, &fetched, &backend, records, now, production)?;
    Ok((checked, fetched, backend.collateral))
}

/// Evidence for one recorded key (spec M10, 11.2): anyone can re-verify it, offline,
/// with the collateral stored beside it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEvidence {
    pub host: String,
    pub key_hash: String,
    pub verified_at: u64,
    pub release: String,
    pub nonce: String,
    pub quote: String,
    pub ccel: String,
    pub key_hashes: Vec<String>,
    pub collateral: StoredCollateral,
}

pub const COLLATERAL_FORMAT: &str = "dcap-qvl-0.7-v3";
pub const MAX_COLLATERAL_JSON: usize = 256 * 1024;

/// The collateral a quote verified against, with a format tag (spec 11.5). Kept as JSON so a
/// library upgrade cannot make the evidence file unreadable: an unknown format fails only
/// that entry's re-verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCollateral {
    pub format: String,
    pub collateral: serde_json::Value,
}

impl StoredCollateral {
    pub fn new(c: &ti_tdx::backend::Collateral) -> StoredCollateral {
        StoredCollateral {
            format: COLLATERAL_FORMAT.into(),
            collateral: serde_json::to_value(c).expect("collateral serializes"),
        }
    }

    /// Format tag and size cap: checked on every re-verification, whatever the backend.
    pub fn check_shape(&self) -> Result<(), Fail> {
        if self.format != COLLATERAL_FORMAT {
            return Err(Fail::new(
                Reason::Collateral,
                format!("unknown stored collateral format {:?}", self.format),
            ));
        }
        let size = serde_json::to_vec(&self.collateral)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size > MAX_COLLATERAL_JSON {
            return Err(Fail::new(
                Reason::Collateral,
                format!("stored collateral is {size} bytes"),
            ));
        }
        Ok(())
    }

    pub fn load(&self) -> Result<ti_tdx::backend::Collateral, Fail> {
        self.check_shape()?;
        serde_json::from_value(self.collateral.clone())
            .map_err(|e| Fail::new(Reason::Collateral, format!("stored collateral: {e}")))
    }
}

/// A host is production unless a staging record lists it (spec 11.5): never a flag. A host in
/// `PRODUCTION_HOSTS` is production always (AB-153), so a staging record cannot relabel it.
pub fn production_for(host: &str, records: &[ReleaseRecord]) -> bool {
    ti_tdx::policy::is_production_host(host)
        || !records
            .iter()
            .any(|r| r.staging && r.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
}

/// Re-run the whole decision for stored evidence at the time it was recorded (spec 11.2):
/// signature with the given backend, nonce and key-list binding, the key in the list, TCB
/// floor, fixed attributes, RTMR replay and the release record. The passing record must be
/// the one the evidence names. Returns that record's version.
pub fn reverify_with(
    ev: &KeyEvidence,
    records: &[ReleaseRecord],
    now: u64,
    backend: &dyn QuoteBackend,
) -> Result<String, Fail> {
    if ev.verified_at > now {
        return Err(Fail::new(
            Reason::Collateral,
            format!("verified_at {} is in the future", ev.verified_at),
        ));
    }
    ev.collateral.check_shape()?;
    let nonce = parse_nonce(&ev.nonce)
        .ok_or_else(|| Fail::new(Reason::NonceMismatch, "stored nonce does not parse"))?;
    let mut keys = Vec::new();
    for k in &ev.key_hashes {
        keys.push(parse_key_hash(k).ok_or_else(|| Fail::new(Reason::Http, "bad stored key hash"))?);
    }
    let key = parse_key_hash(&ev.key_hash)
        .ok_or_else(|| Fail::new(Reason::Http, "bad evidence key hash"))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let quote = b64
        .decode(&ev.quote)
        .map_err(|_| Fail::new(Reason::QuoteSignature, "stored quote is not base64"))?;
    let ccel = b64
        .decode(&ev.ccel)
        .map_err(|_| Fail::new(Reason::EventLog, "stored event log is not base64"))?;
    let verified = backend.verify(&quote, ev.verified_at)?;
    let pass = decide(&Inputs {
        host: &ev.host,
        now: ev.verified_at,
        nonce: &nonce,
        listed_keys: &keys,
        connection_key: &key,
        quote: &verified,
        ccel: &ccel,
        records,
        production: production_for(&ev.host, records),
    })?;
    if pass.record_version != ev.release {
        return Err(Fail::new(
            Reason::MeasurementMismatch,
            format!(
                "evidence names release {:?}, the quote matches {:?}",
                ev.release, pass.record_version
            ),
        ));
    }
    Ok(pass.record_version)
}

/// `reverify_with` the production backend and the evidence's own collateral.
pub fn reverify(ev: &KeyEvidence, records: &[ReleaseRecord], now: u64) -> Result<String, Fail> {
    let collateral = ev.collateral.load()?;
    reverify_with(
        ev,
        records,
        now,
        &ti_tdx::backend::DcapBackend { collateral },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    mod evidence {
        use super::*;
        use ti_tdx::backend::fake::{encode, FakeBackend};
        use ti_tdx::policy::sample::world;

        fn good() -> (KeyEvidence, Vec<ReleaseRecord>) {
            let w = world();
            let b64 = base64::engine::general_purpose::STANDARD;
            let ev = KeyEvidence {
                host: "api.example.test".into(),
                key_hash: hex::encode(w.key),
                verified_at: 1_000,
                release: w.record.version.clone(),
                nonce: hex::encode(w.nonce),
                quote: b64.encode(encode(&w.quote.report, "UpToDate")),
                ccel: b64.encode(&w.ccel),
                key_hashes: vec![hex::encode(w.key)],
                collateral: StoredCollateral {
                    format: COLLATERAL_FORMAT.into(),
                    collateral: serde_json::json!({}),
                },
            };
            (ev, vec![w.record])
        }

        fn reason(r: Result<String, Fail>) -> Reason {
            r.expect_err("must fail").reason
        }

        #[test]
        fn reverify_good_evidence_passes() {
            let (ev, recs) = good();
            assert_eq!(
                reverify_with(&ev, &recs, 2_000, &FakeBackend).unwrap(),
                recs[0].version
            );
        }

        #[test]
        fn reverify_tampered_quote_fails() {
            let (mut ev, recs) = good();
            let w = world();
            let mut r = w.quote.report.clone();
            r.rtmr[2][0] ^= 1;
            ev.quote = base64::engine::general_purpose::STANDARD.encode(encode(&r, "UpToDate"));
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::EventLog
            );
        }

        #[test]
        fn reverify_other_key_or_list_fails() {
            let (mut ev, recs) = good();
            ev.key_hash = hex::encode([1u8; 32]);
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::KeyNotBound
            );
            let (mut ev, recs) = good();
            ev.key_hashes.push(hex::encode([1u8; 32]));
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::BindingMismatch
            );
        }

        #[test]
        fn reverify_future_or_moved_time_fails() {
            let (ev, recs) = good();
            assert_eq!(
                reason(reverify_with(&ev, &recs, 999, &FakeBackend)),
                Reason::Collateral
            );
            let (mut ev, mut recs) = good();
            recs[0].valid_until = 1_500;
            ev.verified_at = 1_600;
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::ReleaseMissing
            );
        }

        #[test]
        fn reverify_wrong_release_name_fails() {
            let (mut ev, recs) = good();
            ev.release = "0.0.9-other".into();
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::MeasurementMismatch
            );
        }

        #[test]
        fn reverify_wrong_host_fails() {
            let (mut ev, recs) = good();
            ev.host = "evil.example.test".into();
            assert_eq!(
                reason(reverify_with(&ev, &recs, 2_000, &FakeBackend)),
                Reason::ReleaseMissing
            );
        }

        #[test]
        fn reverify_staging_evidence_fails_on_a_production_host() {
            let (ev, mut recs) = good();
            // The quote matches only a staging record; the production host's record differs.
            let mut staging = recs[0].clone();
            staging.version = "0.1.0-staging".into();
            staging.staging = true;
            staging.hosts = vec!["cvm-staging.example.test".into()];
            recs[0].mrtd = "11".repeat(48);
            recs.push(staging);
            let mut ev = ev;
            ev.release = "0.1.0-staging".into();
            assert!(production_for(&ev.host, &recs));
            // AB-153: a staging record listing a production host does not make it staging.
            let mut relabel = recs[0].clone();
            relabel.staging = true;
            relabel.hosts = vec!["api.texasinference.ai".into()];
            assert!(production_for("api.texasinference.ai", &[relabel]));
            assert!(reverify_with(&ev, &recs, 2_000, &FakeBackend).is_err());
        }

        #[test]
        fn reverify_production_backend_refuses_a_test_quote() {
            let (ev, recs) = good();
            assert!(
                reverify(&ev, &recs, 2_000).is_err(),
                "a fake quote must never re-verify in production"
            );
            let mut ev2 = ev.clone();
            ev2.collateral.format = "dcap-qvl-0.8-v4".into();
            assert_eq!(reason(reverify(&ev2, &recs, 2_000)), Reason::Collateral);
            let mut ev3 = ev;
            ev3.collateral.collateral = serde_json::json!({"pad": "x".repeat(MAX_COLLATERAL_JSON)});
            assert_eq!(reason(reverify(&ev3, &recs, 2_000)), Reason::Collateral);
        }
    }

    #[test]
    fn target_parsing() {
        let t = Target::parse("https://API.example.test").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("api.example.test", 443));
        assert_eq!(Target::parse("api.example.test:8443").unwrap().port, 8443);
        assert!(Target::parse("https://a.test/path").is_err());
        assert!(Target::parse("https://u@a.test").is_err());
    }

    #[test]
    fn redirects_are_failures() {
        let raw =
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.test/\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_http(raw).unwrap_err().reason, Reason::Http);
    }

    #[test]
    fn chunked_and_length_bodies() {
        assert_eq!(
            parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiXX").unwrap(),
            b"hi"
        );
        assert_eq!(
            parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n1\r\n!\r\n0\r\n\r\n").unwrap(),
            b"hi!"
        );
        assert!(parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhi").is_err());
    }

    #[test]
    fn hostile_chunk_sizes_fail_without_panicking() {
        for size in [
            "ffffffffffffffff",
            "fffffffffffffffe",
            "7fffffffffffffff",
            "10000000",
        ] {
            let raw =
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nAAAA");
            assert_eq!(
                parse_http(raw.as_bytes()).unwrap_err().reason,
                Reason::Http,
                "{size}"
            );
        }
    }
}
