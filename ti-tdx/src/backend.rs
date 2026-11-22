//! Quote signature verification (spec D5, M1, M2).
//!
//! Production uses `DcapBackend`: Intel's DCAP chain through `dcap-qvl` with the
//! Intel production root. The fake backend that accepts unsigned test quotes exists
//! only under `cfg(test)` or the `testkit` feature, which no release build enables.

use crate::reason::{Fail, Reason};
use crate::td::TdReport;

pub use dcap_qvl::QuoteCollateralV3 as Collateral;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub report: TdReport,
    /// `tcbEvaluationDataNumber` of the TCB info and of the QE identity in the collateral that
    /// verified this quote (spec 13.2 item 2). None when the collateral does not carry it.
    pub tcb_eval_data_number: Option<u32>,
    pub qe_tcb_eval_data_number: Option<u32>,
}

pub trait QuoteBackend {
    fn verify(&self, quote: &[u8], now_secs: u64) -> Result<VerifiedQuote, Fail>;
}

/// Verifies against Intel's production root with collateral the caller fetched or cached.
pub struct DcapBackend {
    pub collateral: Collateral,
}

impl QuoteBackend for DcapBackend {
    fn verify(&self, quote: &[u8], now_secs: u64) -> Result<VerifiedQuote, Fail> {
        let v = dcap_qvl::verify::verify(quote, &self.collateral, now_secs)
            .map_err(|e| classify(&format!("{e:#}")))?;
        let td = v
            .report
            .as_td10()
            .ok_or_else(|| Fail::new(Reason::QuoteSignature, "quote is not a TDX quote"))?;
        Ok(VerifiedQuote {
            tcb_status: v.status,
            advisory_ids: v.advisory_ids,
            report: TdReport::from_dcap(td),
            // Read only after verify() accepted the collateral's signatures.
            tcb_eval_data_number: eval_number(&self.collateral.tcb_info),
            qe_tcb_eval_data_number: eval_number(&self.collateral.qe_identity),
        })
    }
}

/// `tcbEvaluationDataNumber` from a TCB info or QE identity JSON body.
pub fn eval_number(body: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("tcbEvaluationDataNumber")?.as_u64()?.try_into().ok()
}

/// Map a dcap-qvl error to a fixed reason. dcap-qvl 0.7.1 reports errors as text
/// (anyhow) or as webpki error names such as `CrlExpired`, so the match is on a
/// lowercased message. Unknown errors stay `quote_signature`: never a pass.
pub fn classify(msg: &str) -> Fail {
    let m = msg.to_ascii_lowercase();
    let reason = if m.contains("debug mode is enabled") {
        Reason::DebugTd
    } else if m.contains("revoked") || m.contains("no matching tcb level") {
        Reason::TcbStatus
    } else if m.contains("expired")
        || m.contains("notvalidyet")
        || m.contains("not yet valid")
        || m.contains("in the future")
        || m.contains("nextupdate")
    {
        Reason::Collateral
    } else {
        Reason::QuoteSignature
    };
    Fail::new(reason, msg)
}

/// Parse a quote without verifying it. Used only to pick the collateral to fetch.
pub fn is_tdx_quote(quote: &[u8]) -> bool {
    dcap_qvl::quote::Quote::parse(quote)
        .map(|q| q.report.as_td10().is_some())
        .unwrap_or(false)
}

#[cfg(any(test, feature = "testkit"))]
pub mod fake {
    //! Test-only quote format: b"TI-TEST-QUOTE\0" || status_len u8 || status || TD body.
    use super::*;

    pub const MAGIC: &[u8] = b"TI-TEST-QUOTE\0";
    /// The TCB evaluation number the fake collateral reports.
    pub const FAKE_EVAL: u32 = 17;

    pub fn encode(report: &TdReport, status: &str) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(status.len() as u8);
        v.extend_from_slice(status.as_bytes());
        v.extend_from_slice(&report.to_bytes());
        v
    }

    pub struct FakeBackend;

    impl QuoteBackend for FakeBackend {
        fn verify(&self, quote: &[u8], _now: u64) -> Result<VerifiedQuote, Fail> {
            let rest = quote
                .strip_prefix(MAGIC)
                .ok_or_else(|| Fail::new(Reason::QuoteSignature, "not a test quote"))?;
            let (&n, rest) = rest
                .split_first()
                .ok_or_else(|| Fail::new(Reason::QuoteSignature, "short"))?;
            let n = n as usize;
            if rest.len() < n {
                return Err(Fail::new(Reason::QuoteSignature, "short"));
            }
            let status = String::from_utf8_lossy(&rest[..n]).to_string();
            let report = TdReport::from_bytes(&rest[n..])
                .ok_or_else(|| Fail::new(Reason::QuoteSignature, "bad body"))?;
            Ok(VerifiedQuote {
                tcb_status: status,
                advisory_ids: vec![],
                report,
                tcb_eval_data_number: Some(FAKE_EVAL),
                qe_tcb_eval_data_number: Some(FAKE_EVAL),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = include_bytes!("../testdata/dcap/tdx_quote");
    const GOOD_COLL: &str = include_str!("../testdata/dcap/tdx_quote_collateral.json");
    const OUTDATED: &[u8] = include_bytes!("../testdata/dcap/tdx_quote_outdated");
    const OUTDATED_COLL: &str = include_str!("../testdata/dcap/tdx_quote_outdated_collateral.json");

    fn coll(s: &str) -> Collateral {
        serde_json::from_str(s).unwrap()
    }

    /// The verification time the fixtures were captured at: inside the TCB info window.
    fn fixture_now(c: &Collateral) -> u64 {
        let issue = |j: &str| {
            let v: serde_json::Value = serde_json::from_str(j).unwrap();
            parse_rfc3339(v["issueDate"].as_str().unwrap())
        };
        issue(&c.tcb_info).max(issue(&c.qe_identity)) + 3600
    }

    fn parse_rfc3339(s: &str) -> u64 {
        // "YYYY-MM-DDTHH:MM:SSZ"
        let y: i64 = s[0..4].parse().unwrap();
        let mo: i64 = s[5..7].parse().unwrap();
        let d: i64 = s[8..10].parse().unwrap();
        let h: i64 = s[11..13].parse().unwrap();
        let mi: i64 = s[14..16].parse().unwrap();
        let se: i64 = s[17..19].parse().unwrap();
        // days from civil (Howard Hinnant)
        let y2 = if mo <= 2 { y - 1 } else { y };
        let era = y2.div_euclid(400);
        let yoe = y2 - era * 400;
        let mp = (mo + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        (days * 86400 + h * 3600 + mi * 60 + se) as u64
    }

    #[test]
    fn real_quote_verifies_up_to_date() {
        let c = coll(GOOD_COLL);
        let now = fixture_now(&c);
        let v = DcapBackend { collateral: c }.verify(GOOD, now).unwrap();
        assert_eq!(v.tcb_status, "UpToDate");
        assert!(is_tdx_quote(GOOD));
    }

    #[test]
    fn real_collateral_reports_its_eval_numbers() {
        // Spec 13.2 item 2: read from the collateral verify() just accepted.
        let c = coll(GOOD_COLL);
        let now = fixture_now(&c);
        let v = DcapBackend { collateral: c }.verify(GOOD, now).unwrap();
        assert_eq!(v.tcb_eval_data_number, Some(17));
        assert_eq!(v.qe_tcb_eval_data_number, Some(17));
        assert_eq!(eval_number("{}"), None);
        assert_eq!(eval_number(r#"{"tcbEvaluationDataNumber": -1}"#), None);
    }

    #[test]
    fn flipped_byte_fails_signature() {
        let c = coll(GOOD_COLL);
        let now = fixture_now(&c);
        let mut q = GOOD.to_vec();
        // Flip a byte inside RTMR0 (header 48 + body offset 328).
        q[48 + 330] ^= 0x01;
        let e = DcapBackend { collateral: c }.verify(&q, now).unwrap_err();
        assert_eq!(e.reason, Reason::QuoteSignature);
    }

    #[test]
    fn outdated_platform_never_passes() {
        // This platform's TCB is below every level Intel lists: dcap-qvl refuses it.
        let c = coll(OUTDATED_COLL);
        let now = fixture_now(&c);
        let e = DcapBackend { collateral: c }
            .verify(OUTDATED, now)
            .unwrap_err();
        assert_eq!(e.reason, Reason::TcbStatus);
    }

    #[test]
    fn test_quote_is_refused_by_the_real_backend() {
        let q = fake::encode(&TdReport::sample(), "UpToDate");
        let c = coll(GOOD_COLL);
        let now = fixture_now(&c);
        let e = DcapBackend { collateral: c }.verify(&q, now).unwrap_err();
        assert_eq!(e.reason, Reason::QuoteSignature);
    }

    #[test]
    fn expired_collateral_is_reported_as_collateral() {
        // Past the TCB info's nextUpdate, and far past the CRL's nextUpdate.
        for later in [40 * 86400, 10 * 365 * 86400] {
            let c = coll(GOOD_COLL);
            let t = fixture_now(&c) + later;
            let e = DcapBackend { collateral: c }.verify(GOOD, t).unwrap_err();
            assert_eq!(e.reason, Reason::Collateral, "at +{later}s: {}", e.detail);
        }
    }

    #[test]
    fn classification_of_every_listed_dcap_message() {
        // checks/t19c/dcap-errors.txt lists every dcap-qvl 0.7.1 text with a trigger word.
        const TABLE: &str = include_str!("../../../checks/t19c/dcap-errors.txt");
        let mut n = 0;
        for line in TABLE
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let (msg, want) = line.split_once('\t').expect("message<TAB>reason");
            let got = classify(msg).reason.to_string();
            assert_eq!(got, want, "classify({msg:?})");
            n += 1;
        }
        assert!(n >= 20, "table has {n} rows");
    }

    #[test]
    fn classification_of_known_messages() {
        assert_eq!(classify("Debug mode is enabled").reason, Reason::DebugTd);
        assert_eq!(
            classify("TCB status is invalid: Revoked").reason,
            Reason::TcbStatus
        );
        assert_eq!(
            classify("CrlExpired { time: 1, next_update: 0 }").reason,
            Reason::Collateral
        );
        assert_eq!(classify("TCBInfo expired").reason, Reason::Collateral);
        assert_eq!(
            classify("Signature is invalid for qe_report in quote").reason,
            Reason::QuoteSignature
        );
    }
}
