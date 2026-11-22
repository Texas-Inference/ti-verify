//! Confidential computing event log (CCEL) parsing and RTMR replay (spec M5).
//!
//! The log is the TCG crypto-agile format: a legacy SHA-1 header event whose data is
//! the Spec ID event (it lists digest algorithms and sizes), then TCG_PCR_EVENT2
//! records. For TDX the record's index is the CC measurement register index:
//! 1 = RTMR0, 2 = RTMR1, 3 = RTMR2, 4 = RTMR3. Replay starts from 48 zero bytes and
//! extends with SHA-384 of (current || digest) for every event except EV_NO_ACTION.

use sha2::{Digest, Sha384};

pub const EV_NO_ACTION: u32 = 0x0000_0003;
pub const ALG_SHA384: u16 = 0x000C;
const MAX_EVENTS: usize = 100_000;
const MAX_EVENT_DATA: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// CC measurement register index (1..=4 for RTMR0..RTMR3).
    pub mr_index: u32,
    pub event_type: u32,
    pub sha384: Option<[u8; 48]>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub events: Vec<Event>,
}

struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.off.checked_add(n).ok_or("overflow")?;
        if end > self.b.len() {
            return Err(format!("truncated at {}", self.off));
        }
        let s = &self.b[self.off..end];
        self.off = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn done(&self) -> bool {
        self.off >= self.b.len()
    }
}

/// Parse a CCEL. Trailing 0xFF or 0x00 padding after the last event is ignored.
pub fn parse(bytes: &[u8]) -> Result<Log, String> {
    let mut r = Reader { b: bytes, off: 0 };
    // Legacy header: pcr u32, type u32, sha1 digest 20, size u32, data.
    let _pcr = r.u32()?;
    let ty = r.u32()?;
    if ty != EV_NO_ACTION {
        return Err("first event is not the Spec ID event".into());
    }
    r.take(20)?;
    let size = r.u32()? as usize;
    if size > MAX_EVENT_DATA {
        return Err("spec id event too large".into());
    }
    let spec = r.take(size)?;
    let sizes = spec_id_digest_sizes(spec)?;

    let mut events = Vec::new();
    while !r.done() {
        let rest = &bytes[r.off..];
        if rest.iter().all(|&b| b == 0xFF) || rest.iter().all(|&b| b == 0x00) {
            break;
        }
        if events.len() >= MAX_EVENTS {
            return Err("too many events".into());
        }
        let mr_index = r.u32()?;
        let event_type = r.u32()?;
        let count = r.u32()?;
        if count as usize > sizes.len() + 4 {
            return Err("digest count out of range".into());
        }
        let mut sha384 = None;
        for _ in 0..count {
            let alg = r.u16()?;
            let len = sizes
                .iter()
                .find(|(a, _)| *a == alg)
                .map(|(_, l)| *l as usize)
                .ok_or_else(|| format!("unknown digest algorithm {alg:#06x}"))?;
            let d = r.take(len)?;
            if alg == ALG_SHA384 {
                if len != 48 {
                    return Err(format!("SHA-384 digest declared with {len} bytes"));
                }
                let mut a = [0u8; 48];
                a.copy_from_slice(d);
                sha384 = Some(a);
            }
        }
        let dlen = r.u32()? as usize;
        if dlen > MAX_EVENT_DATA {
            return Err("event data too large".into());
        }
        let data = r.take(dlen)?.to_vec();
        events.push(Event {
            mr_index,
            event_type,
            sha384,
            data,
        });
    }
    Ok(Log { events })
}

/// TCG_EfiSpecIDEvent: signature[16], platformClass u32, spec minor/major/errata u8x3,
/// uintnSize u8, numberOfAlgorithms u32, then (algId u16, digestSize u16) pairs.
fn spec_id_digest_sizes(spec: &[u8]) -> Result<Vec<(u16, u16)>, String> {
    let mut r = Reader { b: spec, off: 0 };
    let sig = r.take(16)?;
    if !sig.starts_with(b"Spec ID Event03") {
        return Err("bad Spec ID signature".into());
    }
    r.take(4 + 3 + 1)?;
    let n = r.u32()?;
    if n == 0 || n > 16 {
        return Err("bad algorithm count".into());
    }
    let mut v = Vec::new();
    for _ in 0..n {
        v.push((r.u16()?, r.u16()?));
    }
    Ok(v)
}

impl Log {
    /// Replay RTMR0..RTMR3. Fails if an extending event lacks a SHA-384 digest.
    pub fn replay(&self) -> Result<[[u8; 48]; 4], String> {
        let mut rtmr = [[0u8; 48]; 4];
        for (i, e) in self.events.iter().enumerate() {
            if e.event_type == EV_NO_ACTION {
                continue;
            }
            if !(1..=4).contains(&e.mr_index) {
                return Err(format!(
                    "event {i}: register index {} is not an RTMR",
                    e.mr_index
                ));
            }
            let d = e
                .sha384
                .ok_or_else(|| format!("event {i}: no SHA-384 digest"))?;
            let slot = &mut rtmr[(e.mr_index - 1) as usize];
            let mut h = Sha384::new();
            h.update(*slot);
            h.update(d);
            slot.copy_from_slice(&h.finalize());
        }
        Ok(rtmr)
    }

    /// Digests of EFI boot service applications the firmware measured into RTMR1
    /// (EV_EFI_BOOT_SERVICES_APPLICATION, the PE/COFF Authenticode SHA-384 of each image).
    /// For this image that is the unified kernel image, so its digest covers the kernel,
    /// the initrd and the embedded `.cmdline` (review round 3: noble's systemd-stub 255
    /// has no confidential computing measurement path, so nothing else names the command line).
    pub fn boot_app_digests(&self) -> Vec<[u8; 48]> {
        self.events
            .iter()
            .filter(|e| e.mr_index == 2 && e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION)
            .filter_map(|e| e.sha384)
            .collect()
    }
}

pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
/// EFI_GLOBAL_VARIABLE (SecureBoot, PK, KEK) and EFI_IMAGE_SECURITY_DATABASE_GUID (db), as
/// they appear on the wire (mixed endian GUID bytes).
const GLOBAL_VARIABLE: [u8; 16] = guid(
    0x8be4df61,
    0x93ca,
    0x11d2,
    [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
const IMAGE_SECURITY_DATABASE: [u8; 16] = guid(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);
const CERT_X509: [u8; 16] = guid(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// The Secure Boot configuration the firmware measured into RTMR0 (spec 12.7 item 4). Each
/// signature database is the list of its entries: `Ok(sha256 of the DER)` for an X.509
/// certificate, `Err(signature type)` for anything else (a hash entry, for example).
/// One signature database entry: the SHA-256 of an X.509 certificate, or the type GUID of
/// any other entry.
pub type SigEntry = Result<[u8; 32], [u8; 16]>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecureBootConfig {
    pub secure_boot: Option<u8>,
    pub pk: Option<Vec<SigEntry>>,
    pub kek: Option<Vec<SigEntry>>,
    pub db: Option<Vec<SigEntry>>,
}

fn signature_lists(mut b: &[u8]) -> Result<Vec<SigEntry>, String> {
    use sha2::Sha256;
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 28 {
            return Err("truncated EFI_SIGNATURE_LIST header".into());
        }
        let mut ty = [0u8; 16];
        ty.copy_from_slice(&b[..16]);
        let list = u32::from_le_bytes(b[16..20].try_into().unwrap()) as usize;
        let hdr = u32::from_le_bytes(b[20..24].try_into().unwrap()) as usize;
        let sig = u32::from_le_bytes(b[24..28].try_into().unwrap()) as usize;
        if list > b.len() || sig < 16 || list < 28 + hdr || !(list - 28 - hdr).is_multiple_of(sig) {
            return Err("malformed EFI_SIGNATURE_LIST sizes".into());
        }
        let mut body = &b[28 + hdr..list];
        while !body.is_empty() {
            let data = &body[16..sig];
            out.push(if ty == CERT_X509 {
                Ok(Sha256::digest(data).into())
            } else {
                Err(ty)
            });
            body = &body[sig..];
        }
        b = &b[list..];
    }
    Ok(out)
}

/// The UTF-16 name of a UEFI_VARIABLE_DATA event, if the data parses as one.
fn variable_name(d: &[u8]) -> Option<String> {
    let n = u64::from_le_bytes(d.get(16..24)?.try_into().ok()?) as usize;
    let end = n.checked_mul(2)?.checked_add(32)?;
    let raw = d.get(32..end)?;
    char::decode_utf16(raw.chunks(2).map(|p| u16::from_le_bytes([p[0], p[1]])))
        .collect::<Result<String, _>>()
        .ok()
}

impl Log {
    /// One line per RTMR0 and RTMR1 event: register, type, variable name for variable events,
    /// and digest. The live re-check records it (spec 12.9: which events a host can move).
    pub fn describe(&self) -> Vec<String> {
        self.events
            .iter()
            .filter(|e| e.event_type != EV_NO_ACTION && (e.mr_index == 1 || e.mr_index == 2))
            .map(|e| {
                let name = if (0x8000_0001..=0x8000_0002).contains(&e.event_type)
                    || e.event_type == 0x8000_00E0
                    || e.event_type == 0x8000_000C
                {
                    variable_name(&e.data).unwrap_or_default()
                } else {
                    String::new()
                };
                format!(
                    "RTMR{} 0x{:08x} {} {}",
                    e.mr_index - 1,
                    e.event_type,
                    if name.is_empty() {
                        "-".to_string()
                    } else {
                        name
                    },
                    e.sha384.map(hex::encode).unwrap_or_default()
                )
            })
            .collect()
    }

    /// Read SecureBoot, PK, KEK and db from the RTMR0 EV_EFI_VARIABLE_DRIVER_CONFIG events.
    /// Each event's data must hash to its digest (the replay binds only the digests), and a
    /// variable measured twice is refused rather than guessed.
    pub fn secure_boot_config(&self) -> Result<SecureBootConfig, String> {
        let mut c = SecureBootConfig::default();
        for (i, e) in self.events.iter().enumerate() {
            if e.mr_index != 1 || e.event_type != EV_EFI_VARIABLE_DRIVER_CONFIG {
                continue;
            }
            let d = &e.data;
            if d.len() < 32 {
                return Err(format!("event {i}: truncated UEFI_VARIABLE_DATA"));
            }
            let want: [u8; 48] = Sha384::digest(d).into();
            if e.sha384 != Some(want) {
                return Err(format!(
                    "event {i}: variable data does not match its digest"
                ));
            }
            let name_len = u64::from_le_bytes(d[16..24].try_into().unwrap()) as usize;
            let data_len = u64::from_le_bytes(d[24..32].try_into().unwrap()) as usize;
            let name_end = name_len
                .checked_mul(2)
                .and_then(|n| n.checked_add(32))
                .filter(|&n| n <= d.len())
                .ok_or_else(|| format!("event {i}: variable name overruns the event"))?;
            if name_end.checked_add(data_len) != Some(d.len()) {
                return Err(format!(
                    "event {i}: variable data length does not match the event"
                ));
            }
            let name: String = char::decode_utf16(
                d[32..name_end]
                    .chunks(2)
                    .map(|p| u16::from_le_bytes([p[0], p[1]])),
            )
            .map(|r| r.unwrap_or('\u{fffd}'))
            .collect::<String>()
            .trim_end_matches('\0')
            .to_string();
            let vendor = &d[..16];
            let value = &d[name_end..];
            let dup = || format!("event {i}: {name} measured twice");
            match (
                name.as_str(),
                vendor == GLOBAL_VARIABLE,
                vendor == IMAGE_SECURITY_DATABASE,
            ) {
                ("SecureBoot", true, _) => {
                    if c.secure_boot.is_some() {
                        return Err(dup());
                    }
                    if value.len() != 1 {
                        return Err(format!("event {i}: SecureBoot is not one byte"));
                    }
                    c.secure_boot = Some(value[0]);
                }
                ("PK", true, _) | ("KEK", true, _) | ("db", _, true) => {
                    let slot = match name.as_str() {
                        "PK" => &mut c.pk,
                        "KEK" => &mut c.kek,
                        _ => &mut c.db,
                    };
                    if slot.is_some() {
                        return Err(dup());
                    }
                    *slot = Some(
                        signature_lists(value).map_err(|e| format!("event {i}: {name}: {e}"))?,
                    );
                }
                _ => {}
            }
        }
        Ok(c)
    }
}

pub const EV_IPL: u32 = 0x0000_000D;

/// Keys that must never appear on a measured command line, whatever the record says.
pub const FORBIDDEN_KEYS: &[&str] = &[
    "init",
    "rdinit",
    "systemd.unit",
    "rd.systemd.unit",
    "systemd.debug_shell",
    "rd.systemd.debug_shell",
    "rd.break",
    "systemd.confirm_spawn",
    "systemd.run",
    "systemd.run_success_action",
    "systemd.wants",
    "rd.systemd.wants",
    "systemd.mask",
    "rd.systemd.mask",
    "systemd.verity",
    "rd.systemd.verity",
    "systemd.volatile",
    "systemd.firstboot",
    "single",
    "emergency",
    "rescue",
    "s",
    "S",
    "1",
    "-b",
    "-s",
];

/// Tokens every production and staging command line must end with (last value wins).
/// `checks/check-T19c` verifies `confidential/image/lint.py` carries the same lists.
pub const REQUIRED_TOKENS: &[&str] = &[
    "rd.shell=0",
    "rd.emergency=reboot",
    "panic=10",
    "systemd.gpt_auto=0",
    "rd.systemd.gpt_auto=0",
    "systemd.swap=0",
    "systemd.import_credentials=no",
    "lockdown=confidentiality",
    "module.sig_enforce=1",
    "systemd.verity_root_options=panic-on-corruption",
    "efi_pstore.pstore_disable=1",
    "ipv6.disable=1",
];

/// Split a kernel command line the way the kernel's `next_arg` does: spaces separate
/// parameters except inside double quotes, and the quotes are removed.
pub fn kernel_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut any = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                any = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Parameter name with `-` and `_` treated alike, as the kernel and systemd do.
fn key_of(token: &str) -> String {
    token
        .split_once('=')
        .map(|(k, _)| k)
        .unwrap_or(token)
        .replace('-', "_")
}

/// Check pinned tokens against a measured command line. A `key=value` pin must be the
/// last occurrence of that key (the kernel and systemd take the last one). A bare pin
/// must appear as a whole token. Forbidden keys fail.
pub fn check_cmdline(tokens: &[String], pins: &[String]) -> Result<(), String> {
    if tokens.is_empty() {
        return Err("empty command line".into());
    }
    for t in tokens {
        let k = key_of(t);
        if FORBIDDEN_KEYS.iter().any(|f| f.replace('-', "_") == k) {
            return Err(format!("measured command line has forbidden {t:?}"));
        }
    }
    for pin in pins {
        if pin.contains('=') {
            let k = key_of(pin);
            match tokens.iter().rev().find(|t| key_of(t) == k) {
                Some(last)
                    if last.split_once('=').map(|(_, v)| v)
                        == pin.split_once('=').map(|(_, v)| v) => {}
                Some(last) => {
                    return Err(format!(
                        "measured command line sets {last:?}, record pins {pin:?}"
                    ))
                }
                None => return Err(format!("measured command line lacks {pin:?}")),
            }
        } else if !tokens.iter().any(|t| t == pin) {
            return Err(format!("measured command line lacks {pin:?}"));
        }
    }
    Ok(())
}

/// Test helper: build a CCEL with SHA-384 digests.
pub mod build {
    use super::*;

    pub fn header() -> Vec<u8> {
        let mut spec = Vec::new();
        spec.extend_from_slice(b"Spec ID Event03\0");
        spec.extend_from_slice(&0u32.to_le_bytes());
        spec.extend_from_slice(&[0, 2, 0, 2]);
        spec.extend_from_slice(&1u32.to_le_bytes());
        spec.extend_from_slice(&ALG_SHA384.to_le_bytes());
        spec.extend_from_slice(&48u16.to_le_bytes());
        spec.push(0); // vendorInfoSize
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        v.extend_from_slice(&[0u8; 20]);
        v.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        v.extend_from_slice(&spec);
        v
    }

    pub fn event(log: &mut Vec<u8>, mr_index: u32, event_type: u32, data: &[u8]) {
        let digest: [u8; 48] = Sha384::digest(data).into();
        log.extend_from_slice(&mr_index.to_le_bytes());
        log.extend_from_slice(&event_type.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&ALG_SHA384.to_le_bytes());
        log.extend_from_slice(&digest);
        log.extend_from_slice(&(data.len() as u32).to_le_bytes());
        log.extend_from_slice(data);
    }

    /// An event whose digest is of `measured` while its data says something else.
    pub fn event_forged(
        log: &mut Vec<u8>,
        mr_index: u32,
        event_type: u32,
        measured: &[u8],
        data: &[u8],
    ) {
        let digest: [u8; 48] = Sha384::digest(measured).into();
        log.extend_from_slice(&mr_index.to_le_bytes());
        log.extend_from_slice(&event_type.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&ALG_SHA384.to_le_bytes());
        log.extend_from_slice(&digest);
        log.extend_from_slice(&(data.len() as u32).to_le_bytes());
        log.extend_from_slice(data);
    }

    /// A measured UEFI variable (UEFI_VARIABLE_DATA) as OVMF logs it into RTMR0.
    pub fn variable(log: &mut Vec<u8>, db: bool, name: &str, value: &[u8]) {
        let mut d = Vec::new();
        d.extend_from_slice(if db {
            &IMAGE_SECURITY_DATABASE
        } else {
            &GLOBAL_VARIABLE
        });
        d.extend_from_slice(&(name.encode_utf16().count() as u64).to_le_bytes());
        d.extend_from_slice(&(value.len() as u64).to_le_bytes());
        d.extend_from_slice(&utf16(name));
        d.extend_from_slice(value);
        event(log, 1, EV_EFI_VARIABLE_DRIVER_CONFIG, &d);
    }

    /// One EFI_SIGNATURE_LIST holding one X.509 certificate.
    pub fn x509_list(der: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&CERT_X509);
        v.extend_from_slice(&((28 + 16 + der.len()) as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&((16 + der.len()) as u32).to_le_bytes());
        v.extend_from_slice(&[0x11u8; 16]);
        v.extend_from_slice(der);
        v
    }

    /// Secure Boot on with `der` as PK, KEK and db: what a v2 image measures.
    pub fn secure_boot(log: &mut Vec<u8>, on: u8, der: &[u8]) {
        variable(log, false, "SecureBoot", &[on]);
        variable(log, false, "PK", &x509_list(der));
        variable(log, false, "KEK", &x509_list(der));
        variable(log, true, "db", &x509_list(der));
    }

    pub fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn extend(cur: [u8; 48], data: &[u8]) -> [u8; 48] {
        let d: [u8; 48] = Sha384::digest(data).into();
        let mut h = Sha384::new();
        h.update(cur);
        h.update(d);
        h.finalize().into()
    }

    #[test]
    fn replay_matches_manual_extension() {
        let mut log = header();
        event(&mut log, 1, 0x8000_0001, b"firmware");
        event(&mut log, 2, 0x8000_0003, b"kernel");
        event(&mut log, 3, 0x0000_000D, &utf16("roothash=abc rd.shell=0"));
        event(&mut log, 3, EV_NO_ACTION, b"ignored");
        log.extend_from_slice(&[0xFF; 32]);
        let parsed = parse(&log).unwrap();
        let r = parsed.replay().unwrap();
        assert_eq!(r[0], extend([0; 48], b"firmware"));
        assert_eq!(r[1], extend([0; 48], b"kernel"));
        assert_eq!(r[2], extend([0; 48], &utf16("roothash=abc rd.shell=0")));
        assert_eq!(r[3], [0; 48]);
        assert_eq!(parsed.boot_app_digests().len(), 1);
    }

    #[test]
    fn truncated_log_fails() {
        let mut log = header();
        event(&mut log, 1, 1, b"x");
        log.truncate(log.len() - 1);
        assert!(parse(&log).is_err());
    }

    #[test]
    fn non_rtmr_index_fails_replay() {
        let mut log = header();
        event(&mut log, 0, 1, b"mrtd is not replayable");
        assert!(parse(&log).unwrap().replay().is_err());
    }

    #[test]
    fn short_sha384_is_refused_not_a_panic() {
        let mut log = header();
        // Rewrite the declared SHA-384 size from 48 to 32 in the Spec ID event.
        let pos = log
            .windows(4)
            .position(|w| w == [0x0C, 0x00, 48, 0])
            .unwrap();
        log[pos + 2] = 32;
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&ALG_SHA384.to_le_bytes());
        log.extend_from_slice(&[0u8; 32]);
        log.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse(&log).is_err());
    }

    fn pins(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn check(cmd: &str, p: &[&str]) -> Result<(), String> {
        check_cmdline(&kernel_tokens(cmd), &pins(p))
    }

    #[test]
    fn quotes_group_a_parameter() {
        assert_eq!(
            kernel_tokens(r#"roothash=ff ti.note="x roothash=aa11 y" lockdown=none"#),
            vec!["roothash=ff", "ti.note=x roothash=aa11 y", "lockdown=none"]
        );
        // A pin hidden inside a quoted value does not count.
        assert!(check(
            r#"roothash=ff ti.note="x roothash=aa11 y""#,
            &["roothash=aa11"]
        )
        .is_err());
        assert!(check(
            r#"lockdown=none x="lockdown=confidentiality""#,
            &["lockdown=confidentiality"]
        )
        .is_err());
    }

    #[test]
    fn later_override_fails() {
        assert!(check(
            "roothash=aa rd.shell=0 systemd.swap=0 rd.shell=1",
            &["roothash=aa", "rd.shell=0"]
        )
        .is_err());
        assert!(check(
            "roothash=aa rd.shell=0 systemd.swap=0",
            &["roothash=aa", "systemd.swap=0"]
        )
        .is_ok());
    }

    #[test]
    fn dash_and_underscore_spellings_are_the_same_key() {
        assert!(check(
            "systemd.import_credentials=no systemd.import-credentials=yes",
            &["systemd.import_credentials=no"]
        )
        .is_err());
        assert!(check(
            "systemd.gpt_auto=0 systemd.gpt-auto=1",
            &["systemd.gpt_auto=0"]
        )
        .is_err());
    }

    #[test]
    fn roothash_must_match_exactly() {
        assert!(check("roothash=bb22 rd.shell=0", &["roothash=aa11"]).is_err());
        assert!(check("roothash=bb22 rd.shell=0", &["roothash=bb22"]).is_ok());
    }

    #[test]
    fn forbidden_keys_fail_in_both_spellings() {
        for bad in [
            "init=/bin/sh",
            "rdinit=/bin/sh",
            "systemd.debug-shell=1",
            "systemd.debug_shell",
            "systemd.unit=rescue.target",
            "systemd.verity=0",
            "systemd.mask=nftables.service",
            "rd.systemd.debug_shell",
            "systemd.run=/bin/sh",
            "rd.systemd.wants=debug-shell.service",
            "s",
            "-b",
        ] {
            assert!(
                check(&format!("roothash=aa {bad}"), &["roothash=aa"]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn empty_cmdline_fails() {
        assert!(check_cmdline(&[], &pins(&[])).is_err());
    }

    #[test]
    fn boot_application_digest_is_found() {
        let mut log = header();
        event(&mut log, 2, EV_EFI_BOOT_SERVICES_APPLICATION, b"uki");
        event(&mut log, 3, EV_IPL, b"not this");
        let want: [u8; 48] = Sha384::digest(b"uki").into();
        assert_eq!(parse(&log).unwrap().boot_app_digests(), vec![want]);
    }

    #[test]
    fn bad_header_fails() {
        assert!(parse(&[0u8; 8]).is_err());
    }
}
