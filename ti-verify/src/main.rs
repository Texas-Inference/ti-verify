use std::path::PathBuf;
use ti_tdx::backend::Collateral;
use ti_tdx::reason::{Fail, Reason};
use ti_tdx::release::parse_records;
use ti_verify::*;

fn usage() -> ! {
    eprintln!(
        "usage: ti-verify https://HOST[:PORT] --release FILE [--ca FILE] [--collateral FILE] \
         [--save-collateral FILE] [--staging] [--record FILE] [--evidence FILE] [--json]\n       ti-verify https://HOST --dump-measurements [--ca FILE] [--collateral FILE]\n       ti-verify --replay-event-log CCEL\n       ti-verify --lint-records [--now UNIX] [--require-production-host HOST] FILE..."
    );
    std::process::exit(2)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Opts {
    target: String,
    release: PathBuf,
    ca: Option<PathBuf>,
    collateral: Option<PathBuf>,
    save_collateral: Option<PathBuf>,
    evidence: Option<PathBuf>,
    staging: bool,
    record: Option<PathBuf>,
    json: bool,
    dump: bool,
}

fn opts() -> Opts {
    let mut target = None;
    let mut release = None;
    let mut o = Opts {
        target: String::new(),
        release: PathBuf::new(),
        ca: None,
        collateral: None,
        save_collateral: None,
        evidence: None,
        staging: false,
        record: None,
        json: false,
        dump: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--release" => release = Some(val().into()),
            "--ca" => o.ca = Some(val().into()),
            "--collateral" => o.collateral = Some(val().into()),
            "--save-collateral" => o.save_collateral = Some(val().into()),
            "--evidence" => o.evidence = Some(val().into()),
            "--staging" => o.staging = true,
            "--record" => o.record = Some(val().into()),
            "--json" => o.json = true,
            "--dump-measurements" => o.dump = true,
            s if s.starts_with("--") => usage(),
            s => target = Some(s.to_string()),
        }
    }
    o.target = target.unwrap_or_else(|| usage());
    o.release = release.unwrap_or_else(|| if o.dump { PathBuf::new() } else { usage() });
    if o.staging && o.record.is_some() {
        eprintln!("ti-verify: --record refuses a staging host");
        std::process::exit(2);
    }
    o
}

fn run(o: &Opts) -> Result<(Checked, Fetched, String, Collateral), Fail> {
    let target = Target::parse(&o.target)?;
    let records_json = std::fs::read_to_string(&o.release).map_err(|e| {
        Fail::new(
            Reason::ReleaseMissing,
            format!("{}: {e}", o.release.display()),
        )
    })?;
    let records = parse_records(&records_json)
        .map_err(|e| Fail::new(Reason::ReleaseMissing, e.to_string()))?;
    let ca = match &o.ca {
        Some(p) => {
            Some(std::fs::read(p).map_err(|e| Fail::new(Reason::Tls, format!("CA file: {e}")))?)
        }
        None => None,
    };
    let collateral: Option<Collateral> = match &o.collateral {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?;
            Some(
                serde_json::from_str(&s)
                    .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?,
            )
        }
        None => None,
    };
    let (checked, fetched, collateral) = verify_live(
        &target,
        &records,
        ca.as_deref(),
        collateral,
        now(),
        // AB-153: a production host is verified as production whatever --staging says.
        !o.staging || ti_tdx::policy::is_production_host(&target.host),
    )?;
    if let Some(p) = &o.save_collateral {
        let s = serde_json::to_string(&collateral)
            .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?;
        std::fs::write(p, s).map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?;
    }
    Ok((checked, fetched, target.host, collateral))
}

fn dump(o: &Opts) -> Result<serde_json::Value, Fail> {
    let target = Target::parse(&o.target)?;
    let ca = match &o.ca {
        Some(p) => {
            Some(std::fs::read(p).map_err(|e| Fail::new(Reason::Tls, format!("CA file: {e}")))?)
        }
        None => None,
    };
    let cfg = attest_client_config(roots(ca.as_deref())?);
    let nonce = new_nonce();
    let fetched = fetch(&target, cfg, &nonce)?;
    let collateral: Collateral = match &o.collateral {
        Some(p) => serde_json::from_str(
            &std::fs::read_to_string(p)
                .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?,
        )
        .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?,
        None => {
            use base64::Engine;
            let quote = base64::engine::general_purpose::STANDARD
                .decode(&fetched.answer.quote)
                .map_err(|_| Fail::new(Reason::QuoteSignature, "quote is not base64"))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Fail::new(Reason::Collateral, e.to_string()))?
                .block_on(async {
                    dcap_qvl::collateral::CollateralClient::with_default_http(
                        dcap_qvl::collateral::INTEL_PCS_URL,
                    )?
                    .fetch(&quote)
                    .await
                })
                .map_err(|e| Fail::new(Reason::Collateral, format!("Intel PCS: {e:#}")))?
        }
    };
    inspect(
        &nonce,
        &fetched,
        &ti_tdx::backend::DcapBackend { collateral },
        now(),
    )
}

/// AB-153: `ti-verify --lint-records [--now UNIX] [--require-production-host HOST] FILE...`
/// runs every rule on each record that needs no quote. With --require-production-host it fails
/// unless a record valid now, not staging, passing those rules and listing HOST exists: the
/// daily alarm uses it after launch.
fn lint_records(args: &[String]) -> i32 {
    let mut now_s = now();
    let mut host: Option<String> = None;
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--now" => {
                now_s = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--require-production-host" => {
                host = Some(it.next().cloned().unwrap_or_else(|| usage()))
            }
            s if s.starts_with("--") => usage(),
            s => files.push(s.to_string()),
        }
    }
    if files.is_empty() {
        usage()
    }
    let mut bad = 0;
    let mut covered = false;
    for f in &files {
        let recs = match std::fs::read_to_string(f)
            .map_err(|e| e.to_string())
            .and_then(|j| parse_records(&j).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                println!("FAIL: {f}: {e}");
                bad += 1;
                continue;
            }
        };
        for r in recs {
            // Expired records are history, as in release-records.py: noted, never failed.
            if r.valid_until <= now_s {
                println!("note: {f} ({}): expired, not linted", r.version);
                continue;
            }
            match ti_tdx::policy::lint_record(&r) {
                Ok(()) => {
                    println!("ok: {f} ({})", r.version);
                    if let Some(h) = &host {
                        covered |= !r.staging && r.valid_at(now_s) && r.covers_host(h);
                    }
                }
                Err(e) => {
                    println!("FAIL: {f}: {}", e.detail);
                    bad += 1;
                }
            }
        }
    }
    if let Some(h) = &host {
        if !covered {
            println!("FAIL: no valid production record that passes every rule lists {h}: customers cannot verify it");
            bad += 1;
        }
    }
    if bad == 0 {
        println!("PASS: records lint clean");
        0
    } else {
        1
    }
}

fn main() {
    // Spec 13.6: offline replay of a reference boot's event log. No host, no record.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--lint-records") {
        std::process::exit(lint_records(&argv[1..]));
    }
    if argv.first().map(String::as_str) == Some("--replay-event-log") {
        let [_, path] = argv.as_slice() else { usage() };
        let out = std::fs::read(path)
            .map_err(|e| Fail::new(Reason::EventLog, format!("{path}: {e}")))
            .and_then(|b| replay_event_log(&b));
        match out {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(f) => {
                println!("FAIL: {} ({})", f.reason, f.detail);
                std::process::exit(1);
            }
        }
        return;
    }
    let o = opts();
    if o.dump {
        match dump(&o) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(f) => {
                println!("FAIL: {} ({})", f.reason, f.detail);
                std::process::exit(1);
            }
        }
        return;
    }
    match run(&o) {
        Ok((c, f, host, collateral)) => {
            // Third review m3: the quote, nonce, event log and collateral of this PASS, staging
            // included, so anyone can re-verify it. Unlike --record it never touches the
            // attested key list.
            if let Some(p) = &o.evidence {
                let ev = KeyEvidence {
                    collateral: ti_verify::StoredCollateral::new(&collateral),
                    host: host.clone(),
                    key_hash: hex::encode(c.key_hash),
                    verified_at: c.at,
                    release: c.pass.record_version.clone(),
                    nonce: f.answer.nonce.clone(),
                    quote: f.answer.quote.clone(),
                    ccel: f.answer.ccel.clone(),
                    key_hashes: f.answer.key_hashes.clone(),
                };
                if let Err(e) = std::fs::write(p, serde_json::to_string_pretty(&ev).unwrap()) {
                    println!("FAIL: evidence: {e}");
                    std::process::exit(1);
                }
            }
            if let Some(p) = &o.record {
                let ev = KeyEvidence {
                    collateral: ti_verify::StoredCollateral::new(&collateral),
                    host: host.clone(),
                    key_hash: hex::encode(c.key_hash),
                    verified_at: c.at,
                    release: c.pass.record_version.clone(),
                    nonce: f.answer.nonce.clone(),
                    quote: f.answer.quote.clone(),
                    ccel: f.answer.ccel.clone(),
                    key_hashes: f.answer.key_hashes.clone(),
                };
                let mut all: Vec<KeyEvidence> = match std::fs::read_to_string(p) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Err(e) => {
                        println!("FAIL: record: cannot read {}: {e}", p.display());
                        std::process::exit(1);
                    }
                    Ok(s) => {
                        match serde_json::from_str(&s) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("FAIL: record: {} does not parse, refusing to overwrite it: {e}", p.display());
                                std::process::exit(1);
                            }
                        }
                    }
                };
                if !all
                    .iter()
                    .any(|e| e.key_hash == ev.key_hash && e.host == ev.host)
                {
                    all.push(ev);
                }
                if let Err(e) = std::fs::write(p, serde_json::to_string_pretty(&all).unwrap()) {
                    println!("FAIL: record: {e}");
                    std::process::exit(1);
                }
            }
            if o.json {
                println!(
                    "{}",
                    serde_json::json!({"result":"PASS","host":host,"image_version":c.image_version,
                        "key_hash":hex::encode(c.key_hash),"release":c.pass.record_version,
                        "scope":"gateway VM only; worker hop not attested in v0"})
                );
            } else {
                println!(
                    "PASS: {host} {} {} release {} (gateway VM only; worker hop not attested in v0)",
                    c.image_version,
                    hex::encode(c.key_hash),
                    c.pass.record_version
                );
            }
        }
        Err(f) => {
            if o.json {
                println!(
                    "{}",
                    serde_json::json!({"result":"FAIL","reason":f.reason.as_str(),"detail":f.detail})
                );
            } else {
                println!("FAIL: {} ({})", f.reason, f.detail);
            }
            std::process::exit(1);
        }
    }
}
