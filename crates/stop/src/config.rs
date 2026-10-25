//! A guard on the gateway configuration the service is asked by.
//!
//! agentgateway's defaults do not fit this service, and two of them fail in
//! ways nobody would notice:
//!
//! * the request to the authorization service times out after 200 ms unless
//!   the backend policy sets `requestTimeout`. A refusal takes several TPM
//!   operations; at 200 ms the gateway gives up, denies, and the caller never
//!   sees the receipt. Even an allow can miss it.
//! * the body is sent only with `includeRequestBody`, and is silently cut at
//!   `maxRequestBytes`, whose schema default is 0. The request digest would
//!   then describe an empty or truncated body.
//!
//! So the service refuses to start unless the policy file it will hash also
//! says, in so many words: an `extAuthz` pointing at this listener, a
//! `requestTimeout`, `includeRequestBody` with an explicit `maxRequestBytes`
//! no larger than the service accepts, and no `failureMode: allow`.
//!
//! This is a line check over YAML, not a YAML parser: it can refuse a valid
//! configuration written in an unusual style, and that is the intended
//! failure direction. It cannot make a configuration correct, only catch the
//! known ways of getting it wrong.

use crate::http::BODY_MAX;

pub fn check_gateway_config(text: &str, listen: &str) -> Result<(), String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect();
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));

    if !has("extAuthz:") {
        return Err("gateway config has no extAuthz block: tool calls would not ask tactiq-stop".into());
    }
    if !has(listen) {
        return Err(format!("gateway config does not point extAuthz at {listen}"));
    }
    if lines.iter().any(|l| l.replace(' ', "") == "failureMode:allow") {
        return Err("gateway config sets failureMode: allow; an unreachable tactiq-stop would let calls through".into());
    }
    if !has("requestTimeout:") {
        return Err("gateway config sets no requestTimeout for extAuthz; the 200 ms default is shorter than a signed refusal".into());
    }
    if !has("includeRequestBody:") {
        return Err("gateway config does not set includeRequestBody; the request digest would cover no body".into());
    }
    let max = lines
        .iter()
        .find_map(|l| l.strip_prefix("maxRequestBytes:"))
        .ok_or("gateway config sets no maxRequestBytes; its default is 0, an empty body")?
        .trim();
    let n: usize = max
        .parse()
        .map_err(|_| format!("gateway config maxRequestBytes {max:?} is not a number"))?;
    if n == 0 || n > BODY_MAX {
        return Err(format!("gateway config maxRequestBytes {n} must be 1..={BODY_MAX}"));
    }
    if lines.iter().any(|l| l.replace(' ', "") == "allowPartialMessage:true") {
        return Err("gateway config allows partial bodies; the digest would describe a cut request".into());
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
  - routes:
    - backends: []
      policies:
        extAuthz:
          host: 127.0.0.1:49318
          protocol:
            http: {}
          failureMode: deny
          includeRequestBody:
            maxRequestBytes: 1048576
            allowPartialMessage: false
          policies:
            http:
              requestTimeout: 5s
"#;
    const L: &str = "127.0.0.1:49318";

    #[test]
    fn a_complete_config_passes() {
        check_gateway_config(GOOD, L).unwrap();
    }

    #[test]
    fn each_missing_or_dangerous_setting_is_refused() {
        let cases = [
            ("extAuthz:", "noAuthz:"),
            ("127.0.0.1:49318", "127.0.0.1:49999"),
            ("failureMode: deny", "failureMode: allow"),
            ("requestTimeout: 5s", "requestTimeoutX"),
            ("includeRequestBody:", "includeRequestBodyX"),
            ("maxRequestBytes: 1048576", "maxRequestBytes: 0"),
            ("maxRequestBytes: 1048576", "maxRequestBytes: 2000000"),
            ("allowPartialMessage: false", "allowPartialMessage: true"),
        ];
        for (from, to) in cases {
            let bad = GOOD.replace(from, to);
            assert!(check_gateway_config(&bad, L).is_err(), "{from} -> {to} should be refused");
        }
    }

    #[test]
    fn the_shipped_v1_config_is_refused() {
        // TactiQ OS's current agentgateway config has no extAuthz at all.
        let v1 = "binds:\n- port: 49317\n  listeners:\n  - routes:\n    - backends: []\n";
        assert!(check_gateway_config(v1, L).is_err());
    }

    #[test]
    fn comments_do_not_count() {
        let commented = GOOD.replace("requestTimeout: 5s", "# requestTimeout: 5s");
        assert!(check_gateway_config(&commented, L).is_err());
    }
}
