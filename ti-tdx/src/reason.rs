/// The fixed FAIL reasons `ti-verify` prints (spec section 4 and 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Tls,
    Http,
    NonceMismatch,
    KeyNotBound,
    QuoteSignature,
    Collateral,
    BindingMismatch,
    TcbStatus,
    DebugTd,
    TdAttributes,
    EventLog,
    MeasurementMismatch,
    ReleaseMissing,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Tls => "tls",
            Reason::Http => "http",
            Reason::NonceMismatch => "nonce_mismatch",
            Reason::KeyNotBound => "key_not_bound",
            Reason::QuoteSignature => "quote_signature",
            Reason::Collateral => "collateral",
            Reason::BindingMismatch => "binding_mismatch",
            Reason::TcbStatus => "tcb_status",
            Reason::DebugTd => "debug_td",
            Reason::TdAttributes => "td_attributes",
            Reason::EventLog => "event_log",
            Reason::MeasurementMismatch => "measurement_mismatch",
            Reason::ReleaseMissing => "release_missing",
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failed check: the fixed reason plus a detail line for operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub reason: Reason,
    pub detail: String,
}

impl Fail {
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Fail {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for Fail {}
