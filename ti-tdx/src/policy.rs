//! The decision after the quote signature verified (spec D2, D6, M4, M5, M13).

use crate::backend::VerifiedQuote;
use crate::binding::{report_data, NONCE_LEN};
use crate::ccel;
use crate::reason::{Fail, Reason};
use crate::release::{hex_n, ReleaseRecord};
use crate::td::{attr, TdReport};

/// Statuses that never pass, whatever a release record says (spec M4).
pub const KNOWN_PLATFORMS: &[&str] = &["gcp-tdx", "server1-tdx"];

/// AB-153: hosts customers verify in production. A staging record may never list one, and
/// `ti-verify` treats them as production whatever flag or record says otherwise. Must equal
/// `confidential/releases/production-hosts.txt` (check-T19c compares them).
pub const PRODUCTION_HOSTS: &[&str] = &["api.texasinference.ai"];

pub fn is_production_host(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    PRODUCTION_HOSTS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
}

pub const TCB_FLOOR_REFUSED: &[&str] = &["Revoked", "OutOfDate", "OutOfDateConfigurationNeeded"];

pub struct Inputs<'a> {
    pub host: &'a str,
    pub now: u64,
    pub nonce: &'a [u8; NONCE_LEN],
    /// Key hashes the VM listed in its answer.
    pub listed_keys: &'a [[u8; 32]],
    /// The key the TLS connection actually presented.
    pub connection_key: &'a [u8; 32],
    pub quote: &'a VerifiedQuote,
    pub ccel: &'a [u8],
    pub records: &'a [ReleaseRecord],
    /// True when verifying a production host: staging records are skipped.
    pub production: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    pub record_version: String,
}

pub fn decide(i: &Inputs) -> Result<Pass, Fail> {
    if !i.listed_keys.contains(i.connection_key) {
        return Err(Fail::new(
            Reason::KeyNotBound,
            format!(
                "connection key {} not in the attested list",
                hex::encode(i.connection_key)
            ),
        ));
    }
    let r = &i.quote.report;
    let expect = report_data(i.nonce, i.listed_keys);
    if r.report_data != expect {
        return Err(Fail::new(
            Reason::BindingMismatch,
            "report data does not bind this nonce and key list",
        ));
    }
    check_tcb_floor(&i.quote.tcb_status)?;
    check_attributes_fixed(r)?;

    let log = ccel::parse(i.ccel).map_err(|e| Fail::new(Reason::EventLog, e))?;
    let replay = log.replay().map_err(|e| Fail::new(Reason::EventLog, e))?;
    for (n, (got, want)) in replay.iter().zip(r.rtmr.iter()).take(3).enumerate() {
        if got != want {
            return Err(Fail::new(
                Reason::EventLog,
                format!("event log replay of RTMR{n} does not match the quote"),
            ));
        }
    }
    let boot_apps = log.boot_app_digests();
    let secure_boot = log.secure_boot_config();

    let candidates: Vec<&ReleaseRecord> = i
        .records
        .iter()
        .filter(|rec| {
            rec.valid_at(i.now) && rec.covers_host(i.host) && !(i.production && rec.staging)
        })
        .collect();
    if candidates.is_empty() {
        return Err(Fail::new(
            Reason::ReleaseMissing,
            format!("no valid release record covers {}", i.host),
        ));
    }

    let mut last: Option<Fail> = None;
    for rec in candidates {
        match check_against(rec, i.quote, &boot_apps, &secure_boot) {
            Ok(()) => {
                return Ok(Pass {
                    record_version: rec.version.clone(),
                })
            }
            Err(f) => last = Some(f),
        }
    }
    Err(last.expect("at least one candidate"))
}

fn check_tcb_floor(status: &str) -> Result<(), Fail> {
    if TCB_FLOOR_REFUSED
        .iter()
        .any(|s| s.eq_ignore_ascii_case(status))
    {
        return Err(Fail::new(
            Reason::TcbStatus,
            format!("TCB status {status} is below the floor"),
        ));
    }
    Ok(())
}

/// Attribute rules no release record can change.
fn check_attributes_fixed(r: &TdReport) -> Result<(), Fail> {
    let a = r.td_attributes_u64();
    if a & attr::DEBUG != 0 {
        return Err(Fail::new(Reason::DebugTd, "TD DEBUG attribute is set"));
    }
    if a & attr::MIGRATABLE != 0 {
        return Err(Fail::new(Reason::TdAttributes, "TD is MIGRATABLE"));
    }
    if a & attr::SEPT_VE_DISABLE == 0 {
        return Err(Fail::new(
            Reason::TdAttributes,
            "SEPT_VE_DISABLE is not set",
        ));
    }
    if r.mr_signer_seam != [0u8; 48] {
        return Err(Fail::new(
            Reason::TdAttributes,
            "TDX module not signed by Intel (MRSIGNERSEAM non-zero)",
        ));
    }
    Ok(())
}

fn tcb_accepted(rec: &ReleaseRecord, q: &VerifiedQuote) -> bool {
    if q.tcb_status == "UpToDate" && q.advisory_ids.is_empty() {
        return true;
    }
    rec.accepted_tcb.iter().any(|a| {
        a.status == q.tcb_status && q.advisory_ids.iter().all(|id| a.advisories.contains(id))
    })
}

#[cfg(any(test, feature = "testkit"))]
pub fn sample_uki_cmdline() -> String {
    format!(
        "roothash={} {}",
        "ab".repeat(32),
        ccel::REQUIRED_TOKENS.join(" ")
    )
}

/// SHA-256 of Debian's public OVMF snakeoil test certificate (`PkKek-1-snakeoil.pem`). Anyone can
/// sign with it, so no record may pin it (spec 12.2 item 4).
pub const SNAKEOIL_CERT_SHA256: [u8; 32] = [
    0x5e, 0x2a, 0x88, 0x6d, 0x7d, 0x56, 0xdc, 0x91, 0x8f, 0x16, 0x80, 0x63, 0x66, 0xd4, 0xc2, 0xe1,
    0xc0, 0xde, 0x23, 0xa6, 0xf1, 0x02, 0x6b, 0xa5, 0xdf, 0x14, 0xf0, 0x37, 0x0f, 0x0e, 0x19, 0xa0,
];

/// Spec 13.2: the same rule as checks/t19c/release-records.py, which refuses uppercase.
fn is_lower_hex<const N: usize>(s: &str) -> bool {
    s.len() == N * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// AB-153: every rule on a record that needs no quote. `check_against` runs it first, and
/// `ti-verify --lint-records` runs it alone so the daily alarm counts only records that could
/// verify the gateway.
pub fn lint_record(rec: &ReleaseRecord) -> Result<(), Fail> {
    let refuse = |why: String| {
        Fail::new(
            Reason::ReleaseMissing,
            format!("release {}: {why}", rec.version),
        )
    };
    if rec
        .hosts
        .iter()
        .any(|h| h.ends_with('.') || h.contains(':'))
    {
        return Err(refuse(
            "hosts must be bare names (no trailing dot, no port)".into(),
        ));
    }
    if rec.staging && rec.hosts.iter().any(|h| is_production_host(h)) {
        return Err(refuse(
            "a staging record may not list a production host".into(),
        ));
    }
    if !KNOWN_PLATFORMS.contains(&rec.platform.as_str()) {
        return Err(refuse(format!("unknown platform {:?}", rec.platform)));
    }
    if rec.mr_owner_unpinned && rec.platform != "gcp-tdx" {
        return Err(refuse(
            "only a gcp-tdx record may leave mr_owner unpinned".into(),
        ));
    }
    // AB-153: a Google record is staging only until gcp-tdx records are bound to Google's
    // FMSPCs (spec 13.8). Same rule as checks/t19c/release-records.py.
    if rec.platform == "gcp-tdx" && !rec.staging {
        return Err(refuse(
            "a production record must be server1-tdx (gcp-tdx records are staging only)".into(),
        ));
    }
    if rec.platform == "gcp-tdx" && rec.machine_type.is_none() {
        return Err(refuse("a gcp-tdx record must name its machine type".into()));
    }
    // Spec 13.2: a server #1 record pins the TDX module and a collateral floor and says what it
    // ran on. A Google record carries no provenance: Google owns the firmware and launch.
    if rec.platform == "server1-tdx" {
        if rec.mr_seam.is_none() {
            return Err(refuse("a server1-tdx record must pin mr_seam".into()));
        }
        if !rec.mr_seam.as_deref().is_some_and(is_lower_hex::<48>) {
            return Err(refuse("mr_seam is not 96 lowercase hex".into()));
        }
        if rec.min_tcb_eval_data_number.unwrap_or(0) == 0 {
            return Err(refuse(
                "a server1-tdx record must set min_tcb_eval_data_number".into(),
            ));
        }
        match &rec.provenance {
            None => return Err(refuse("a server1-tdx record must carry provenance".into())),
            Some(p) => {
                if !is_lower_hex::<32>(&p.firmware_sha256)
                    || !is_lower_hex::<32>(&p.td_launch_config_sha256)
                {
                    return Err(refuse("malformed provenance".into()));
                }
            }
        }
    } else if rec.provenance.is_some() {
        return Err(refuse(
            "only a server1-tdx record carries provenance".into(),
        ));
    }
    let tokens = ccel::kernel_tokens(&rec.uki_cmdline);
    let roothash_ok = tokens
        .iter()
        .rev()
        .find(|t| t.starts_with("roothash="))
        .map(|t| {
            t.len() == "roothash=".len() + 64
                && t["roothash=".len()..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
        })
        .unwrap_or(false);
    if !roothash_ok {
        return Err(refuse("command line does not pin a 64-hex roothash".into()));
    }
    let required: Vec<String> = ccel::REQUIRED_TOKENS
        .iter()
        .map(|s| s.to_string())
        .collect();
    ccel::check_cmdline(&tokens, &required)
        .map_err(|e| refuse(format!("command line is not hardened: {e}")))?;
    hex_n::<48>(&rec.uki_authenticode_sha384)
        .ok_or_else(|| refuse("malformed uki_authenticode_sha384".into()))?;
    let sb_cert = rec.secure_boot_cert_sha256.as_deref().ok_or_else(|| {
        refuse("record does not pin Secure Boot (secure_boot_cert_sha256)".into())
    })?;
    let sb_cert =
        hex_n::<32>(sb_cert).ok_or_else(|| refuse("malformed secure_boot_cert_sha256".into()))?;
    if sb_cert == SNAKEOIL_CERT_SHA256 {
        return Err(refuse(
            "pins the public OVMF snakeoil test certificate".into(),
        ));
    }
    let hex_fields: [(&str, &str, usize); 8] = [
        ("mrtd", &rec.mrtd, 48),
        ("rtmr0", &rec.rtmr0, 48),
        ("rtmr1", &rec.rtmr1, 48),
        ("rtmr2", &rec.rtmr2, 48),
        ("xfam", &rec.xfam, 8),
        ("td_attributes", &rec.td_attributes, 8),
        ("mr_config_id", &rec.mr_config_id, 48),
        ("mr_owner_config", &rec.mr_owner_config, 48),
    ];
    for (name, v, n) in hex_fields {
        if v.len() != n * 2 || hex::decode(v).is_err() {
            return Err(refuse(format!("malformed {name}")));
        }
    }
    if !rec.mr_owner_unpinned && (rec.mr_owner.len() != 96 || hex::decode(&rec.mr_owner).is_err()) {
        return Err(refuse("malformed mr_owner".into()));
    }
    Ok(())
}

fn check_against(
    rec: &ReleaseRecord,
    q: &VerifiedQuote,
    boot_apps: &[[u8; 48]],
    secure_boot: &Result<ccel::SecureBootConfig, String>,
) -> Result<(), Fail> {
    lint_record(rec)?;
    let uki = hex_n::<48>(&rec.uki_authenticode_sha384).ok_or_else(|| {
        Fail::new(
            Reason::ReleaseMissing,
            format!("release {}: malformed uki_authenticode_sha384", rec.version),
        )
    })?;
    let sb_cert = hex_n::<32>(rec.secure_boot_cert_sha256.as_deref().unwrap_or_default())
        .ok_or_else(|| {
            Fail::new(
                Reason::ReleaseMissing,
                format!("release {}: malformed secure_boot_cert_sha256", rec.version),
            )
        })?;
    if !tcb_accepted(rec, q) {
        return Err(Fail::new(
            Reason::TcbStatus,
            format!(
                "TCB status {} with advisories {:?} not accepted by release {}",
                q.tcb_status, q.advisory_ids, rec.version
            ),
        ));
    }
    let r = &q.report;
    let mm = |field: &str| {
        Fail::new(
            Reason::MeasurementMismatch,
            format!("{field} differs from release {}", rec.version),
        )
    };
    let bad = |field: &str| {
        Fail::new(
            Reason::ReleaseMissing,
            format!("release {} has a malformed {field}", rec.version),
        )
    };

    let td_attr = hex_n::<8>(&rec.td_attributes).ok_or_else(|| bad("td_attributes"))?;
    if r.td_attributes != td_attr {
        return Err(Fail::new(
            Reason::TdAttributes,
            format!("TD attributes differ from release {}", rec.version),
        ));
    }
    let checks: [(&str, &str, &[u8]); 8] = [
        ("mrtd", &rec.mrtd, &r.mr_td),
        ("rtmr0", &rec.rtmr0, &r.rtmr[0]),
        ("rtmr1", &rec.rtmr1, &r.rtmr[1]),
        ("rtmr2", &rec.rtmr2, &r.rtmr[2]),
        ("xfam", &rec.xfam, &r.xfam),
        ("mr_config_id", &rec.mr_config_id, &r.mr_config_id),
        ("mr_owner", &rec.mr_owner, &r.mr_owner),
        ("mr_owner_config", &rec.mr_owner_config, &r.mr_owner_config),
    ];
    for (name, want_hex, got) in checks {
        if name == "mr_owner" && rec.mr_owner_unpinned {
            continue;
        }
        let want = hex::decode(want_hex).map_err(|_| bad(name))?;
        if want.len() != got.len() {
            return Err(bad(name));
        }
        if want != got {
            return Err(mm(name));
        }
    }
    if let Some(seam) = &rec.mr_seam {
        let want = hex_n::<48>(seam).ok_or_else(|| bad("mr_seam"))?;
        if r.mr_seam != want {
            return Err(mm("mr_seam"));
        }
    }
    if let Some(floor) = rec.min_tcb_eval_data_number {
        for (what, got) in [
            ("TCB info", q.tcb_eval_data_number),
            ("QE identity", q.qe_tcb_eval_data_number),
        ] {
            match got {
                Some(n) if n >= floor => {}
                _ => {
                    return Err(Fail::new(
                        Reason::Collateral,
                        format!(
                            "{what} TCB evaluation {got:?} is below release {}'s floor {floor}",
                            rec.version
                        ),
                    ))
                }
            }
        }
    }
    let sb = secure_boot
        .as_ref()
        .map_err(|e| Fail::new(Reason::EventLog, e.clone()))?;
    if sb.secure_boot != Some(1) {
        return Err(Fail::new(
            Reason::EventLog,
            format!(
                "the event log shows Secure Boot {:?}, release {} needs 1",
                sb.secure_boot, rec.version
            ),
        ));
    }
    let only_ours: &[ccel::SigEntry] = &[Ok(sb_cert)];
    for (name, list) in [("PK", &sb.pk), ("KEK", &sb.kek), ("db", &sb.db)] {
        if list.as_deref() != Some(only_ours) {
            return Err(Fail::new(
                Reason::EventLog,
                format!(
                    "{name} in the event log is not exactly the certificate release {} pins",
                    rec.version
                ),
            ));
        }
    }
    if !boot_apps.contains(&uki) {
        return Err(Fail::new(
            Reason::EventLog,
            format!(
                "the event log shows no boot of the UKI release {} names",
                rec.version
            ),
        ));
    }
    Ok(())
}

/// A consistent quote, event log and release record for tests (and the testkit build).
#[cfg(any(test, feature = "testkit"))]
pub mod sample {
    use super::*;
    use crate::ccel::build;

    /// Stands in for the DER certificate of the release's Secure Boot key.
    pub const SAMPLE_SB_CERT: &[u8] = b"sample secure boot certificate der";

    pub struct World {
        pub nonce: [u8; 32],
        pub key: [u8; 32],
        pub ccel: Vec<u8>,
        pub quote: VerifiedQuote,
        pub record: ReleaseRecord,
    }

    pub fn world() -> World {
        let nonce = [5u8; 32];
        let key = [9u8; 32];
        let mut ccel = build::header();
        build::secure_boot(&mut ccel, 1, SAMPLE_SB_CERT);
        build::event(&mut ccel, 1, 0x8000_000A, b"firmware config");
        build::event(&mut ccel, 2, 0x8000_0003, b"uki pe image");
        let replay = crate::ccel::parse(&ccel).unwrap().replay().unwrap();
        let mut report = TdReport::sample();
        report.rtmr[0] = replay[0];
        report.rtmr[1] = replay[1];
        report.rtmr[2] = replay[2];
        report.report_data = report_data(&nonce, &[key]);
        let record = ReleaseRecord {
            version: "0.1.0-test".into(),
            platform: "server1-tdx".into(),
            machine_type: None,
            hosts: vec!["api.example.test".into()],
            staging: false,
            valid_from: 0,
            valid_until: u64::MAX,
            image_digest: None,
            mrtd: hex::encode(report.mr_td),
            rtmr0: hex::encode(report.rtmr[0]),
            rtmr1: hex::encode(report.rtmr[1]),
            rtmr2: hex::encode(report.rtmr[2]),
            xfam: hex::encode(report.xfam),
            td_attributes: hex::encode(report.td_attributes),
            mr_config_id: "00".repeat(48),
            mr_owner: "00".repeat(48),
            mr_owner_config: "00".repeat(48),
            mr_owner_unpinned: false,
            mr_seam: Some(hex::encode(report.mr_seam)),
            accepted_tcb: vec![],
            uki_authenticode_sha384: hex::encode(<sha2::Sha384 as sha2::Digest>::digest(
                b"uki pe image",
            )),
            uki_cmdline: sample_uki_cmdline(),
            secure_boot_cert_sha256: Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                SAMPLE_SB_CERT,
            ))),
            min_tcb_eval_data_number: Some(17),
            provenance: Some(crate::release::GatewayProvenance {
                firmware_sha256: "11".repeat(32),
                td_launch_config_sha256: "22".repeat(32),
            }),
        };
        World {
            nonce,
            key,
            ccel,
            quote: VerifiedQuote {
                tcb_status: "UpToDate".into(),
                advisory_ids: vec![],
                report,
                tcb_eval_data_number: Some(17),
                qe_tcb_eval_data_number: Some(17),
            },
            record,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ccel::build;
    use crate::release::AcceptedTcb;

    pub use super::sample::*;

    fn run(w: &World) -> Result<Pass, Fail> {
        let records = vec![w.record.clone()];
        decide(&Inputs {
            host: "api.example.test",
            now: 1_000,
            nonce: &w.nonce,
            listed_keys: &[w.key],
            connection_key: &w.key,
            quote: &w.quote,
            ccel: &w.ccel,
            records: &records,
            production: true,
        })
    }

    fn reason(w: &World) -> Reason {
        run(w).unwrap_err().reason
    }

    /// A Google staging record, verified as a staging host (production false).
    fn gcp_world() -> World {
        let mut w = world();
        w.record.platform = "gcp-tdx".into();
        w.record.machine_type = Some("c3-standard-4".into());
        w.record.staging = true;
        w.record.mr_seam = None;
        w.record.min_tcb_eval_data_number = None;
        w.record.provenance = None;
        w
    }

    fn run_staging(w: &World) -> Result<Pass, Fail> {
        let records = vec![w.record.clone()];
        decide(&Inputs {
            host: "api.example.test",
            now: 1_000,
            nonce: &w.nonce,
            listed_keys: &[w.key],
            connection_key: &w.key,
            quote: &w.quote,
            ccel: &w.ccel,
            records: &records,
            production: false,
        })
    }

    #[test]
    fn staging_record_listing_a_production_host_is_refused() {
        // AB-153: a staging record cannot relabel a production host.
        let mut w = gcp_world();
        w.record.hosts.push("API.texasinference.ai".into());
        let e = run_staging(&w).unwrap_err();
        assert_eq!(e.reason, Reason::ReleaseMissing);
        assert!(e.detail.contains("production host"), "{}", e.detail);
        assert!(lint_record(&w.record).is_err());
        let mut w = gcp_world();
        w.record.hosts.push("api.texasinference.ai.".into());
        assert!(lint_record(&w.record)
            .unwrap_err()
            .detail
            .contains("bare names"));
        assert!(is_production_host("api.texasinference.ai."));
    }

    #[test]
    fn lint_record_passes_a_good_record_and_refuses_a_malformed_one() {
        let w = world();
        assert!(lint_record(&w.record).is_ok());
        let mut r = w.record.clone();
        r.mrtd = "00".into();
        assert!(lint_record(&r)
            .unwrap_err()
            .detail
            .contains("malformed mrtd"));
        let mut r = w.record.clone();
        r.uki_cmdline = "console=ttyS0".into();
        assert!(lint_record(&r).is_err());
    }

    #[test]
    fn production_gcp_record_is_refused() {
        let mut w = gcp_world();
        assert!(run_staging(&w).is_ok(), "{:?}", run_staging(&w));
        w.record.staging = false;
        let e = run_staging(&w).unwrap_err();
        assert_eq!(e.reason, Reason::ReleaseMissing);
        assert!(e.detail.contains("staging only"), "{}", e.detail);
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn good_world_passes() {
        assert_eq!(run(&world()).unwrap().record_version, "0.1.0-test");
    }

    #[test]
    fn replayed_nonce_fails_binding() {
        let mut w = world();
        w.nonce = [6u8; 32];
        assert_eq!(reason(&w), Reason::BindingMismatch);
    }

    #[test]
    fn other_key_bound_fails_binding() {
        let mut w = world();
        w.quote.report.report_data = report_data(&w.nonce, &[[8u8; 32]]);
        assert_eq!(reason(&w), Reason::BindingMismatch);
    }

    #[test]
    fn connection_key_not_listed_fails() {
        let w = world();
        let records = vec![w.record.clone()];
        let other = [1u8; 32];
        let e = decide(&Inputs {
            host: "api.example.test",
            now: 1_000,
            nonce: &w.nonce,
            listed_keys: &[w.key],
            connection_key: &other,
            quote: &w.quote,
            ccel: &w.ccel,
            records: &records,
            production: true,
        })
        .unwrap_err();
        assert_eq!(e.reason, Reason::KeyNotBound);
    }

    #[test]
    fn debug_bit_fails() {
        let mut w = world();
        let a = w.quote.report.td_attributes_u64() | attr::DEBUG;
        w.quote.report.td_attributes = a.to_le_bytes();
        assert_eq!(reason(&w), Reason::DebugTd);
    }

    #[test]
    fn migratable_fails() {
        let mut w = world();
        let a = w.quote.report.td_attributes_u64() | attr::MIGRATABLE;
        w.quote.report.td_attributes = a.to_le_bytes();
        assert_eq!(reason(&w), Reason::TdAttributes);
    }

    #[test]
    fn sept_ve_disable_required() {
        let mut w = world();
        let a = w.quote.report.td_attributes_u64() & !attr::SEPT_VE_DISABLE;
        w.quote.report.td_attributes = a.to_le_bytes();
        assert_eq!(reason(&w), Reason::TdAttributes);
    }

    fn world_with_secure_boot(on: u8, extra_db: bool) -> World {
        let mut w = world();
        let mut ccel = build::header();
        build::variable(&mut ccel, false, "SecureBoot", &[on]);
        build::variable(&mut ccel, false, "PK", &build::x509_list(SAMPLE_SB_CERT));
        build::variable(&mut ccel, false, "KEK", &build::x509_list(SAMPLE_SB_CERT));
        let mut db = build::x509_list(SAMPLE_SB_CERT);
        if extra_db {
            db.extend(build::x509_list(b"a host's own certificate"));
        }
        build::variable(&mut ccel, true, "db", &db);
        build::event(&mut ccel, 2, 0x8000_0003, b"uki pe image");
        let replay = crate::ccel::parse(&ccel).unwrap().replay().unwrap();
        w.quote.report.rtmr[0] = replay[0];
        w.quote.report.rtmr[1] = replay[1];
        w.record.rtmr0 = hex::encode(replay[0]);
        w.record.rtmr1 = hex::encode(replay[1]);
        w.ccel = ccel;
        w
    }

    #[test]
    fn secure_boot_world_helper_passes() {
        assert!(run(&world_with_secure_boot(1, false)).is_ok());
    }

    #[test]
    fn secure_boot_off_fails_even_when_the_record_matches() {
        // Spec 12.7 item 4: a record made from a Secure Boot-off boot must not verify.
        assert_eq!(reason(&world_with_secure_boot(0, false)), Reason::EventLog);
    }

    #[test]
    fn extra_db_certificate_fails() {
        assert_eq!(reason(&world_with_secure_boot(1, true)), Reason::EventLog);
    }

    #[test]
    fn record_without_secure_boot_pin_is_refused() {
        let mut w = world();
        w.record.secure_boot_cert_sha256 = None;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn unpinned_mr_owner_on_gcp_accepts_another_vm() {
        let mut w = gcp_world();
        w.record.mr_owner = "ab".repeat(48);
        assert_eq!(
            run_staging(&w).unwrap_err().reason,
            Reason::MeasurementMismatch
        );
        w.record.mr_owner_unpinned = true;
        assert!(run_staging(&w).is_ok());
    }

    #[test]
    fn unpinned_mr_owner_off_gcp_is_refused() {
        let mut w = world();
        w.record.mr_owner_unpinned = true;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    /// Spec 13.2: a server #1 record as the reference boot would write it.
    fn server1_world() -> World {
        world()
    }

    #[test]
    fn server1_record_passes() {
        assert!(run(&server1_world()).is_ok(), "{:?}", run(&server1_world()));
    }

    #[test]
    fn server1_record_without_mr_seam_is_refused() {
        let mut w = server1_world();
        w.record.mr_seam = None;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn server1_record_without_eval_floor_is_refused() {
        let mut w = server1_world();
        w.record.min_tcb_eval_data_number = None;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn server1_record_without_provenance_is_refused() {
        let mut w = server1_world();
        w.record.provenance = None;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn malformed_provenance_is_refused() {
        let mut w = server1_world();
        w.record.provenance.as_mut().unwrap().firmware_sha256 = "zz".into();
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn server1_record_with_zero_eval_floor_is_refused() {
        let mut w = server1_world();
        w.record.min_tcb_eval_data_number = Some(0);
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn uppercase_server1_fields_are_refused() {
        let mut w = server1_world();
        w.record.provenance.as_mut().unwrap().firmware_sha256 = "AB".repeat(32);
        assert_eq!(reason(&w), Reason::ReleaseMissing);
        let mut w = server1_world();
        w.record.mr_seam = Some("AB".repeat(48));
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn gateway_record_with_platform_id_does_not_parse() {
        // Spec 13.2 item 4: platform_id stays out of gateway records until ti-verify checks it.
        let mut v = serde_json::to_value(&server1_world().record).unwrap();
        v["platform_id"] = serde_json::json!({"ppid": "00".repeat(16), "fmspc": "00".repeat(6)});
        assert!(crate::release::parse_records(&v.to_string()).is_err());
        v.as_object_mut().unwrap().remove("platform_id");
        assert!(crate::release::parse_records(&v.to_string()).is_ok());
    }

    #[test]
    fn provenance_on_gcp_is_refused() {
        let mut w = gcp_world();
        w.record.provenance = server1_world().record.provenance;
        assert_eq!(run_staging(&w).unwrap_err().reason, Reason::ReleaseMissing);
    }

    #[test]
    fn gcp_record_without_machine_type_is_refused() {
        let mut w = gcp_world();
        w.record.machine_type = None;
        let e = run_staging(&w).unwrap_err();
        assert_eq!(e.reason, Reason::ReleaseMissing);
        assert!(e.detail.contains("machine type"), "{}", e.detail);
    }

    #[test]
    fn eval_floor_above_tcb_info_fails() {
        let mut w = server1_world();
        w.record.min_tcb_eval_data_number = Some(18);
        w.quote.qe_tcb_eval_data_number = Some(18);
        assert_eq!(reason(&w), Reason::Collateral);
    }

    #[test]
    fn eval_floor_above_qe_identity_fails() {
        let mut w = server1_world();
        w.record.min_tcb_eval_data_number = Some(18);
        w.quote.tcb_eval_data_number = Some(18);
        assert_eq!(reason(&w), Reason::Collateral);
    }

    #[test]
    fn collateral_without_eval_number_fails_a_floor() {
        let mut w = server1_world();
        w.quote.qe_tcb_eval_data_number = None;
        assert_eq!(reason(&w), Reason::Collateral);
    }

    #[test]
    fn snakeoil_record_is_refused() {
        let mut w = world();
        w.record.secure_boot_cert_sha256 = Some(hex::encode(SNAKEOIL_CERT_SHA256));
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn other_secure_boot_certificate_fails() {
        let mut w = world();
        w.record.secure_boot_cert_sha256 = Some("ab".repeat(32));
        assert_eq!(reason(&w), Reason::EventLog);
    }

    #[test]
    fn forged_variable_data_fails() {
        // The replay binds digests only: data claiming SecureBoot 1 over a digest of 0 fails.
        let mut w = world();
        let mut ccel = build::header();
        let mut off = Vec::new();
        build::variable(&mut off, false, "SecureBoot", &[0]);
        let mut on = Vec::new();
        build::variable(&mut on, false, "SecureBoot", &[1]);
        let data = |v: &[u8]| v[v.len() - (32 + 20 + 1)..].to_vec();
        build::event_forged(
            &mut ccel,
            1,
            crate::ccel::EV_EFI_VARIABLE_DRIVER_CONFIG,
            &data(&off),
            &data(&on),
        );
        build::variable(&mut ccel, false, "PK", &build::x509_list(SAMPLE_SB_CERT));
        build::variable(&mut ccel, false, "KEK", &build::x509_list(SAMPLE_SB_CERT));
        build::variable(&mut ccel, true, "db", &build::x509_list(SAMPLE_SB_CERT));
        build::event(&mut ccel, 2, 0x8000_0003, b"uki pe image");
        let replay = crate::ccel::parse(&ccel).unwrap().replay().unwrap();
        w.quote.report.rtmr[0] = replay[0];
        w.record.rtmr0 = hex::encode(replay[0]);
        w.ccel = ccel;
        let e = run(&w).unwrap_err();
        assert_eq!(e.reason, Reason::EventLog);
        assert!(
            e.detail.contains("does not match its digest"),
            "{}",
            e.detail
        );
    }

    #[test]
    fn secure_boot_measured_twice_fails() {
        let mut w = world();
        let mut ccel = build::header();
        build::secure_boot(&mut ccel, 1, SAMPLE_SB_CERT);
        build::variable(&mut ccel, false, "SecureBoot", &[1]);
        build::event(&mut ccel, 2, 0x8000_0003, b"uki pe image");
        let replay = crate::ccel::parse(&ccel).unwrap().replay().unwrap();
        w.quote.report.rtmr[0] = replay[0];
        w.record.rtmr0 = hex::encode(replay[0]);
        w.ccel = ccel;
        assert_eq!(reason(&w), Reason::EventLog);
    }

    #[test]
    fn changed_rtmr_fails() {
        // A changed image changes the event log and RTMRs together: the replay still
        // matches, the record does not.
        let mut w = world();
        let mut ccel = build::header();
        build::secure_boot(&mut ccel, 1, SAMPLE_SB_CERT);
        build::event(&mut ccel, 1, 0x8000_000A, b"firmware config");
        build::event(&mut ccel, 2, 0x8000_0003, b"a different uki");
        let replay = crate::ccel::parse(&ccel).unwrap().replay().unwrap();
        w.quote.report.rtmr[1] = replay[1];
        w.ccel = ccel;
        assert_eq!(reason(&w), Reason::MeasurementMismatch);
    }

    #[test]
    fn log_that_does_not_replay_to_quote_fails() {
        let mut w = world();
        w.quote.report.rtmr[2] = [0xEE; 48];
        assert_eq!(reason(&w), Reason::EventLog);
    }

    #[test]
    fn record_with_unhardened_cmdline_is_refused() {
        let mut w = world();
        w.record.uki_cmdline = w
            .record
            .uki_cmdline
            .replace("systemd.swap=0", "systemd.swap=1");
        assert_eq!(reason(&w), Reason::ReleaseMissing);
        let mut w = world();
        w.record.uki_cmdline.push_str(" init=/bin/sh");
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn unpinned_roothash_is_refused() {
        let mut w = world();
        w.record.uki_cmdline = w
            .record
            .uki_cmdline
            .replace(&format!("roothash={}", "ab".repeat(32)), "roothash=");
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn uki_not_in_the_event_log_fails() {
        // The record names one UKI; the log shows the firmware booted another whose
        // RTMR1 happens to be pinned too (a record written for a different image).
        let mut w = world();
        w.record.uki_authenticode_sha384 = hex::encode([0x77u8; 48]);
        assert_eq!(reason(&w), Reason::EventLog);
    }

    #[test]
    fn unknown_platform_is_refused() {
        let mut w = world();
        w.record.platform = "laptop".into();
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn no_record_fails() {
        let mut w = world();
        w.record.hosts = vec!["other.test".into()];
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn expired_record_fails() {
        let mut w = world();
        w.record.valid_until = 10;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn staging_record_never_verifies_production() {
        let mut w = world();
        w.record.staging = true;
        assert_eq!(reason(&w), Reason::ReleaseMissing);
    }

    #[test]
    fn out_of_date_never_passes_even_if_listed() {
        let mut w = world();
        w.quote.tcb_status = "OutOfDate".into();
        w.record.accepted_tcb = vec![AcceptedTcb {
            status: "OutOfDate".into(),
            advisories: vec![],
        }];
        assert_eq!(reason(&w), Reason::TcbStatus);
    }

    #[test]
    fn sw_hardening_needs_listing_with_every_advisory() {
        let mut w = world();
        w.quote.tcb_status = "SWHardeningNeeded".into();
        w.quote.advisory_ids = vec!["INTEL-SA-00615".into(), "INTEL-SA-00999".into()];
        assert_eq!(reason(&w), Reason::TcbStatus);
        w.record.accepted_tcb = vec![AcceptedTcb {
            status: "SWHardeningNeeded".into(),
            advisories: vec!["INTEL-SA-00615".into()],
        }];
        assert_eq!(reason(&w), Reason::TcbStatus);
        w.record.accepted_tcb[0]
            .advisories
            .push("INTEL-SA-00999".into());
        assert!(run(&w).is_ok());
    }

    #[test]
    fn host_set_owner_fields_must_match() {
        let mut w = world();
        w.quote.report.mr_owner = [1u8; 48];
        assert_eq!(reason(&w), Reason::MeasurementMismatch);
    }

    #[test]
    fn non_intel_seam_signer_fails() {
        let mut w = world();
        w.quote.report.mr_signer_seam = [1u8; 48];
        assert_eq!(reason(&w), Reason::TdAttributes);
    }
}
