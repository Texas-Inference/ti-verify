//! The TD report fields `ti-verify` checks, decoupled from the quote library.
//!
//! The byte layout is the 584-byte TDREPORT body of a TDX 1.0 quote (Intel TDX DCAP
//! Quoting Library API, TD Quote Body). `to_bytes` and `from_bytes` exist so tests can
//! build synthetic reports; production reports come from `dcap-qvl` after the
//! signature chain has been verified.

pub const BODY_LEN: usize = 584;

/// TD attribute bits (Intel TDX Module ABI, TDATTRIBUTES).
pub mod attr {
    pub const DEBUG: u64 = 1 << 0;
    pub const SEPT_VE_DISABLE: u64 = 1 << 28;
    pub const MIGRATABLE: u64 = 1 << 29;
    pub const PKS: u64 = 1 << 30;
    pub const KL: u64 = 1 << 31;
    pub const PERFMON: u64 = 1 << 63;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReport {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

impl TdReport {
    pub fn td_attributes_u64(&self) -> u64 {
        u64::from_le_bytes(self.td_attributes)
    }

    pub fn from_dcap(r: &dcap_qvl::quote::TDReport10) -> Self {
        TdReport {
            tee_tcb_svn: r.tee_tcb_svn,
            mr_seam: r.mr_seam,
            mr_signer_seam: r.mr_signer_seam,
            seam_attributes: r.seam_attributes,
            td_attributes: r.td_attributes,
            xfam: r.xfam,
            mr_td: r.mr_td,
            mr_config_id: r.mr_config_id,
            mr_owner: r.mr_owner,
            mr_owner_config: r.mr_owner_config,
            rtmr: [r.rt_mr0, r.rt_mr1, r.rt_mr2, r.rt_mr3],
            report_data: r.report_data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BODY_LEN);
        v.extend_from_slice(&self.tee_tcb_svn);
        v.extend_from_slice(&self.mr_seam);
        v.extend_from_slice(&self.mr_signer_seam);
        v.extend_from_slice(&self.seam_attributes);
        v.extend_from_slice(&self.td_attributes);
        v.extend_from_slice(&self.xfam);
        v.extend_from_slice(&self.mr_td);
        v.extend_from_slice(&self.mr_config_id);
        v.extend_from_slice(&self.mr_owner);
        v.extend_from_slice(&self.mr_owner_config);
        for r in &self.rtmr {
            v.extend_from_slice(r);
        }
        v.extend_from_slice(&self.report_data);
        debug_assert_eq!(v.len(), BODY_LEN);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != BODY_LEN {
            return None;
        }
        let mut off = 0usize;
        fn take<const N: usize>(b: &[u8], off: &mut usize) -> [u8; N] {
            let mut a = [0u8; N];
            a.copy_from_slice(&b[*off..*off + N]);
            *off += N;
            a
        }
        Some(TdReport {
            tee_tcb_svn: take::<16>(b, &mut off),
            mr_seam: take::<48>(b, &mut off),
            mr_signer_seam: take::<48>(b, &mut off),
            seam_attributes: take::<8>(b, &mut off),
            td_attributes: take::<8>(b, &mut off),
            xfam: take::<8>(b, &mut off),
            mr_td: take::<48>(b, &mut off),
            mr_config_id: take::<48>(b, &mut off),
            mr_owner: take::<48>(b, &mut off),
            mr_owner_config: take::<48>(b, &mut off),
            rtmr: [
                take::<48>(b, &mut off),
                take::<48>(b, &mut off),
                take::<48>(b, &mut off),
                take::<48>(b, &mut off),
            ],
            report_data: take::<64>(b, &mut off),
        })
    }

    /// A plausible production-shaped report for tests: SEPT_VE_DISABLE set, nothing else.
    pub fn sample() -> Self {
        TdReport {
            tee_tcb_svn: [0; 16],
            mr_seam: [0x11; 48],
            mr_signer_seam: [0; 48],
            seam_attributes: [0; 8],
            td_attributes: attr::SEPT_VE_DISABLE.to_le_bytes(),
            xfam: 0x0000_0000_0006_1ae7u64.to_le_bytes(),
            mr_td: [0x22; 48],
            mr_config_id: [0; 48],
            mr_owner: [0; 48],
            mr_owner_config: [0; 48],
            rtmr: [[0x30; 48], [0x31; 48], [0x32; 48], [0x33; 48]],
            report_data: [0; 64],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_round_trips() {
        let mut r = TdReport::sample();
        r.report_data = [0xab; 64];
        let b = r.to_bytes();
        assert_eq!(b.len(), BODY_LEN);
        assert_eq!(TdReport::from_bytes(&b).unwrap(), r);
    }

    #[test]
    fn report_data_is_last_64_bytes() {
        let mut r = TdReport::sample();
        r.report_data = [0xcd; 64];
        let b = r.to_bytes();
        assert_eq!(&b[520..584], &[0xcd; 64]);
        // MRTD at offset 136, RTMR0 at 328 (TD Quote Body layout).
        assert_eq!(&b[136..184], &[0x22; 48]);
        assert_eq!(&b[328..376], &[0x30; 48]);
    }

    #[test]
    fn wrong_length_refused() {
        assert!(TdReport::from_bytes(&[0u8; 583]).is_none());
    }
}
