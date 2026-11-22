//! Release records (spec D7 and M13): what a verified VM must measure to.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedTcb {
    /// A TCB status such as "SWHardeningNeeded". "UpToDate" is always accepted.
    pub status: String,
    /// Every advisory ID the quote reports must be listed here.
    #[serde(default)]
    pub advisories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    pub version: String,
    /// "gcp-tdx" or "server1-tdx".
    pub platform: String,
    /// For gcp-tdx, the machine type the reference boot used (RTMR0 depends on it).
    #[serde(default)]
    pub machine_type: Option<String>,
    /// Hosts this record may verify. `ti-verify` refuses a record that does not list the host.
    pub hosts: Vec<String>,
    /// A staging record never verifies a production host and `--record` refuses it.
    pub staging: bool,
    /// Unix seconds.
    pub valid_from: u64,
    pub valid_until: u64,
    /// Informational in v0: not covered by the quote (spec R1).
    #[serde(default)]
    pub image_digest: Option<String>,
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub xfam: String,
    pub td_attributes: String,
    #[serde(default = "zero48")]
    pub mr_config_id: String,
    #[serde(default = "zero48")]
    pub mr_owner: String,
    /// gcp-tdx only (spec 12.18): Google sets MROWNER per VM, so a record may leave it unpinned
    /// and survive the VM being recreated. The host chooses MROWNER freely, so pinning it gives
    /// no protection against the host. Refused on any other platform.
    #[serde(default)]
    pub mr_owner_unpinned: bool,
    #[serde(default = "zero48")]
    pub mr_owner_config: String,
    /// Optional pin of the TDX module measurement.
    #[serde(default)]
    pub mr_seam: Option<String>,
    #[serde(default)]
    pub accepted_tcb: Vec<AcceptedTcb>,
    /// PE/COFF Authenticode SHA-384 of the unified kernel image (`lint.py --uki FILE
    /// --record-fields`). The firmware measures it into RTMR1, so it binds the kernel,
    /// initrd and embedded command line of the exact image the record describes.
    pub uki_authenticode_sha384: String,
    /// The `.cmdline` section of that UKI, exactly. ti-verify checks it against the
    /// required and forbidden tokens; the digest above is what ties it to the boot.
    pub uki_cmdline: String,
    /// SHA-256 of the DER certificate that must be the only entry of PK, KEK and db, with
    /// SecureBoot 1, in the event log (spec 12.7 item 4). Records without it are refused:
    /// a Secure Boot-off boot lets a host replace the kernel command line (spec 12.1).
    #[serde(default)]
    pub secure_boot_cert_sha256: Option<String>,
    /// Spec 13.2 item 2. The lowest Intel TCB evaluation data number the TCB info and the QE
    /// identity in the verified collateral may carry. Required on server1-tdx.
    #[serde(default)]
    pub min_tcb_eval_data_number: Option<u32>,
    /// Spec 13.2 item 3. What the reference boot ran on. Not covered by the quote and not
    /// checked by ti-verify. Required on server1-tdx, refused on gcp-tdx.
    #[serde(default)]
    pub provenance: Option<GatewayProvenance>,
}

/// Unchecked facts about a server1-tdx reference boot (spec 13.2 item 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayProvenance {
    /// SHA-256 of the enrolled OVMF image (runbook 8.8 step 2).
    pub firmware_sha256: String,
    /// SHA-256 of the written QEMU command line (RFC-40 F16).
    pub td_launch_config_sha256: String,
}

fn zero48() -> String {
    "00".repeat(48)
}

impl ReleaseRecord {
    pub fn valid_at(&self, now: u64) -> bool {
        self.valid_from <= now && now < self.valid_until
    }

    pub fn covers_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
    }
}

/// Decode a hex field of exactly N bytes.
pub fn hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Load every record in a JSON array or a single JSON object.
pub fn parse_records(json: &str) -> anyhow::Result<Vec<ReleaseRecord>> {
    let v: serde_json::Value = serde_json::from_str(json)?;
    if v.is_array() {
        Ok(serde_json::from_value(v)?)
    } else {
        Ok(vec![serde_json::from_value(v)?])
    }
}
