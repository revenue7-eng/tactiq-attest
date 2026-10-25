//! A guard on the gateway configuration the service is asked by.
//!
//! At agentgateway's pinned revision (d204f9c) two defaults do not fit this
//! service, and both fail without anyone noticing:
//!
//! * the request to the authorization service gets a 200 ms timeout
//!   (`BackendRequestTimeout` in `http/ext_authz.rs`) unless the backend
//!   policy sets `requestTimeout`. A refusal takes several TPM operations;
//!   at 200 ms the gateway gives up and denies, and the caller never sees the
//!   receipt. Even an allow can miss it.
//! * the body is sent only with `includeRequestBody`, and is cut at
//!   `maxRequestBytes`, whose schema default at that revision is 0. The
//!   request digest would then describe an empty or truncated body.
//!
//! What this guard is, and what it is not
//! --------------------------------------
//! It is a line check over YAML, kept deliberately small because it runs in
//! the device's trusted code. It refuses the known ways of getting the
//! settings wrong, and it refuses anything ambiguous (two `extAuthz` blocks,
//! two `maxRequestBytes`, an unparseable timeout). It errs towards refusing
//! to start, which denies every call.
//!
//! It does not check structure: it cannot see whether every route that
//! reaches a tool is covered by the `extAuthz` it found. That check needs a
//! YAML parser and belongs where one is cheap, in the build of the operating
//! image (tactiq-os), which parses the shipped configuration and fails the
//! build unless every listener carries this `extAuthz` at listener level.
//! The configuration then lives on the dm-verity root and its digest is in
//! every stop record.

use crate::http::BODY_MAX;

/// The smallest `requestTimeout` accepted. A signed refusal is four TPM
/// operations; on an SPI TPM that is around a second, more when the agent is
/// using the TPM at the same time.
pub const MIN_TIMEOUT_MS: u64 = 3000;

fn norm(v: &str) -> String {
    v.trim().trim_matches(|c| c == '"' || c == '\'').trim().to_string()
}

/// `key: value` lines with comments stripped, keys trimmed. A `key:` line
/// with nothing after it (a block start) yields an empty value.
fn entries(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter_map(|l| {
            let l = l.trim().trim_start_matches("- ").trim();
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), norm(v)))
        })
        .collect()
}

fn parse_duration_ms(v: &str) -> Option<u64> {
    if let Some(n) = v.strip_suffix("ms") {
        return n.trim().parse().ok();
    }
    if let Some(n) = v.strip_suffix('s') {
        return n.trim().parse::<u64>().ok().map(|s| s * 1000);
    }
    None
}

pub fn check_gateway_config(text: &str, listen: &str) -> Result<(), String> {
    if text.contains('{') {
        return Err("gateway config uses inline YAML mappings; write them as blocks so they can be checked".into());
    }
    let e = entries(text);
    let all = |k: &str| e.iter().filter(|(key, _)| key == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
    let one = |k: &str| -> Result<String, String> {
        match all(k).as_slice() {
            [v] => Ok(v.to_string()),
            [] => Err(format!("gateway config has no {k}")),
            _ => Err(format!("gateway config has more than one {k}; the guard cannot tell which applies")),
        }
    };

    if all("extAuthz").len() != 1 {
        return Err("gateway config must have exactly one extAuthz block (at listener level)".into());
    }
    if one("host")? != listen {
        return Err(format!("gateway config: the single host entry must be the extAuthz target {listen}"));
    }
    if one("failureMode")? != "deny" {
        return Err("gateway config must set failureMode: deny explicitly".into());
    }
    let t = one("requestTimeout")?;
    match parse_duration_ms(&t) {
        Some(ms) if ms >= MIN_TIMEOUT_MS => {}
        Some(ms) => return Err(format!("gateway config requestTimeout {ms} ms is below {MIN_TIMEOUT_MS} ms")),
        None => return Err(format!("gateway config requestTimeout {t:?} is not a duration like 5s or 5000ms")),
    }
    if all("includeRequestBody").len() != 1 {
        return Err("gateway config must set includeRequestBody exactly once".into());
    }
    let max = one("maxRequestBytes")?;
    let n: usize = max
        .parse()
        .map_err(|_| format!("gateway config maxRequestBytes {max:?} is not a number"))?;
    if n == 0 || n > BODY_MAX {
        return Err(format!("gateway config maxRequestBytes {n} must be 1..={BODY_MAX}"));
    }
    if one("allowPartialMessage")? != "false" {
        return Err("gateway config must set allowPartialMessage: false explicitly".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
binds:
- port: 49317
  listeners:
  - policies:
      extAuthz:
        host: 127.0.0.1:49318
        protocol:
          http:
            path: null
        failureMode: deny
        includeRequestBody:
          maxRequestBytes: 1048576
          allowPartialMessage: false
        policies:
          http:
            requestTimeout: 5s
    routes:
    - backends: []
"#;
    const L: &str = "127.0.0.1:49318";

    #[test]
    fn a_complete_config_passes() {
        check_gateway_config(GOOD, L).unwrap();
    }

    #[test]
    fn each_missing_weak_or_ambiguous_setting_is_refused() {
        let cases = [
            ("extAuthz:", "noAuthz:"),
            ("host: 127.0.0.1:49318", "host: 127.0.0.1:49999"),
            ("failureMode: deny", "failureMode: allow"),
            ("failureMode: deny", "failureMode: \"allow\""),
            ("failureMode: deny", "failureMode:\t'allow'"),
            ("failureMode: deny", "denyX: 1"),
            ("requestTimeout: 5s", "requestTimeout: 100ms"),
            ("requestTimeout: 5s", "requestTimeout: soon"),
            ("requestTimeout: 5s", "requestTimeoutX: 5s"),
            ("includeRequestBody:", "includeRequestBodyX:"),
            ("maxRequestBytes: 1048576", "maxRequestBytes: 0"),
            ("maxRequestBytes: 1048576", "maxRequestBytes: 2000000"),
            ("allowPartialMessage: false", "allowPartialMessage: true"),
            ("allowPartialMessage: false", "allowPartialMessageX: false"),
        ];
        for (from, to) in cases {
            let bad = GOOD.replace(from, to);
            assert!(check_gateway_config(&bad, L).is_err(), "{from} -> {to:?} should be refused");
        }
    }

    #[test]
    fn duplicates_and_inline_maps_are_refused() {
        let twice = format!("{GOOD}\n- port: 1\n  listeners:\n  - policies:\n      extAuthz:\n        host: 127.0.0.1:49318\n");
        assert!(check_gateway_config(&twice, L).is_err());
        let other_host = GOOD.replace("    - backends: []", "    - backends:\n      - host: 10.0.0.1:80");
        assert!(check_gateway_config(&other_host, L).is_err(), "a second host entry is ambiguous");
        let inline = GOOD.replace("failureMode: deny", "x: {failureMode: allow}\n        failureMode: deny");
        assert!(check_gateway_config(&inline, L).is_err());
    }

    #[test]
    fn quoted_values_are_read_as_values() {
        let quoted = GOOD.replace("failureMode: deny", "failureMode: 'deny'").replace("requestTimeout: 5s", "requestTimeout: \"5000ms\"");
        check_gateway_config(&quoted, L).unwrap();
    }

    #[test]
    fn the_shipped_v1_config_is_refused() {
        let v1 = "binds:\n- port: 49317\n  listeners:\n  - routes:\n    - backends: []\n";
        assert!(check_gateway_config(v1, L).is_err());
    }

    #[test]
    fn comments_do_not_count() {
        let commented = GOOD.replace("requestTimeout: 5s", "# requestTimeout: 5s");
        assert!(check_gateway_config(&commented, L).is_err());
    }
}
