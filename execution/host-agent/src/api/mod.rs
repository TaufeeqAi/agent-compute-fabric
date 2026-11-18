//! The host API (contract §10): the semantic model as wire types.
//!
//! * **The contract governs the schema, not the reverse** (INV-036). The envelope, the command set,
//!   the states and the failure classes are transcribed from §10–§12 and checked against those
//!   tables by tests; `execution/contracts/host-api.json` is generated from these types.
//! * **Versioned and strict.** `protocol` must name a supported major; every type denies unknown
//!   fields, so a field that narrows what a sandbox may do can never be silently ignored (VR-2).
//! * **Ids, not names, for anything that mutates.** Names are aliases accepted only by read-only
//!   lookups (ID-5).
//! * **Transport is a replaceable mechanism.** These types are carried as length-delimited JSON
//!   frames over mutual TLS or the local socket; nothing here knows which.

pub mod command;
pub mod envelope;
pub mod response;
pub mod schema;

pub use command::*;
pub use envelope::*;
pub use response::*;

/// Protocol family and major version. A change that is not backward compatible bumps the major.
pub const PROTOCOL_FAMILY: &str = "acf.host";
pub const PROTOCOL_MAJOR: u32 = 2;
/// The protocol identifier this host speaks.
pub const PROTOCOL: &str = "acf.host/2";

/// The features of this protocol version that a host can advertise in `host.info` (VR-3). A request
/// that uses a feature that is not listed is refused. `signed_decision` and `incremental_output` are
/// deliberately absent: the interfaces are reserved and the implementations are deferred (AU-11, OU-5).
///
/// A host advertises a feature only while it offers it: [`ALLOWLIST_NETWORK`] is listed only where
/// the backend supports the mode and the safety profile lists it (§20.1).
pub const FEATURES: &[&str] = &[ALLOWLIST_NETWORK, "change_cursor", "host_modes", "operation_list", "quarantine_release", "scope_tags"];

/// The feature that says network mode `allowlist` is offered by this host, now.
pub const ALLOWLIST_NETWORK: &str = "allowlist_network";

/// What a refusal may say about a request that did not decode: what was wrong, and never what the
/// request said.
///
/// serde names the offending value or key in its message, and a request can hold anything in
/// either: a secret pasted where a reference belongs, which SC-1 says is kept nowhere, or bytes
/// chosen to end up in somebody's log. What serde *expected* comes from this crate's own types, so
/// that part is kept and the message stays useful.
pub(crate) fn decode_error(e: &serde_json::Error) -> String {
    let text = e.to_string();
    // ` at line 3 column 14`, present when the request was decoded from bytes: where, with no content.
    let is_position = |tail: &str| {
        let mut words = tail.split(' ').filter(|w| !w.is_empty());
        let number = |w: Option<&str>| w.is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()));
        words.next() == Some("at")
            && words.next() == Some("line")
            && number(words.next())
            && words.next() == Some("column")
            && number(words.next())
            && words.next().is_none()
    };
    let (body, position) = match text.rfind(" at line ") {
        Some(i) if is_position(&text[i..]) => (&text[..i], &text[i..]),
        _ => (text.as_str(), ""),
    };
    // The last `, expected …` is serde's own: whatever the request held comes before it.
    let expected = body.rfind(", expected ").map_or("", |i| &body[i..]);
    let kind_of = |rest: &str| rest.chars().take_while(|c| c.is_ascii_alphabetic() || *c == ' ').collect::<String>().trim().to_owned();
    let said = if let Some(rest) = body.strip_prefix("invalid type: ") {
        format!("invalid type: {}{expected}", kind_of(rest))
    } else if let Some(rest) = body.strip_prefix("invalid value: ") {
        format!("invalid value: {}{expected}", kind_of(rest))
    } else if body.starts_with("unknown field ") && body.ends_with(", there are no fields") {
        // Checked before `expected` is used: here serde appended no `, expected …` of its own, so one
        // found in the text would be the request's.
        "unknown field: this object takes no fields".to_owned()
    } else if body.starts_with("unknown variant ") || body.starts_with("unknown field ") {
        let what = if body.starts_with("unknown variant ") { "unknown variant" } else { "unknown field" };
        if expected.is_empty() { what.to_owned() } else { format!("{what}{expected}") }
    } else if body.contains('"') {
        // Not a shape this function knows, and it quotes something: say nothing of it.
        "the request does not match the published schema".to_owned()
    } else {
        // Syntax errors, missing or duplicate fields of our own types, lengths, and the fixed
        // messages of this crate's own validators: none of them repeats request content.
        body.to_owned()
    };
    format!("{said}{position}")
}

/// Largest response frame the host will ever send (and a client's default receive limit).
pub const MAX_RESPONSE_FRAME: usize = 64 * 1024 * 1024;

/// Room reserved in a response for everything that is *not* captured output: ids, metrics, resource
/// evidence, artifact references, notes, and JSON escaping.
pub const RESPONSE_METADATA_SLACK: usize = 1024 * 1024;

/// The most captured output (stdout + stderr, raw bytes) a single response can carry. Output travels
/// base64-encoded (4 bytes of text per 3 of data), so a run that stays under the profile ceilings must
/// still fit in one frame: otherwise it would succeed and its result could never be delivered. Profile
/// validation enforces this, so the guarantee does not depend on anyone choosing sensible numbers.
pub const MAX_RESULT_OUTPUT_BYTES: u64 = ((MAX_RESPONSE_FRAME - RESPONSE_METADATA_SLACK) / 4 * 3) as u64;

const _: () = assert!(
    (MAX_RESULT_OUTPUT_BYTES as usize).div_ceil(3) * 4 + RESPONSE_METADATA_SLACK <= MAX_RESPONSE_FRAME,
    "the output budget must leave room for the response metadata",
);

/// VR-1: an unknown or unsupported major version is refused before anything is recorded.
pub fn protocol_supported(protocol: &str) -> bool {
    protocol == PROTOCOL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_major_is_supported_and_the_identifier_is_family_slash_major() {
        assert_eq!(PROTOCOL, format!("{PROTOCOL_FAMILY}/{PROTOCOL_MAJOR}"));
        assert!(protocol_supported("acf.host/2"));
        for other in ["acf.host/1", "acf.host/3", "acf.host", "acf.host/2.1", "ACF.HOST/2", ""] {
            assert!(!protocol_supported(other), "{other}");
        }
    }

    /// SC-1, and plain hygiene: whatever a request held where it did not belong, the refusal does not
    /// repeat it. Each case decodes a real request with `MATERIAL` in the wrong place, in every shape
    /// serde reports, and the message must still say what was expected.
    #[test]
    fn a_refusal_for_an_undecodable_request_never_repeats_what_the_request_said() {
        use serde::Deserialize;

        const MATERIAL: &str = "hunter2, expected `anything`, there are no fields";
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reference {
            #[serde(rename = "ref")]
            _name: String,
        }
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Nothing {}
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Mode {
            None,
            Allowlist,
        }
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            #[serde(default)]
            _secret: Option<Reference>,
            #[serde(default)]
            _mode: Option<Mode>,
            #[serde(default)]
            _count: Option<u8>,
            #[serde(default)]
            _empty: Option<Nothing>,
        }
        let quoted = serde_json::to_string(MATERIAL).unwrap();
        let cases = [
            (format!(r#"{{"_secret": {quoted}}}"#), "invalid type: string, expected struct Reference"),
            (r#"{"_secret": {"ref": 7}}"#.to_owned(), "invalid type: integer, expected a string"),
            (format!(r#"{{"_secret": {{"ref": "x", {quoted}: 1}}}}"#), "unknown field, expected `ref`"),
            (format!(r#"{{"_mode": {quoted}}}"#), "unknown variant, expected `none` or `allowlist`"),
            (format!(r#"{{{quoted}: 1}}"#), "unknown field, expected one of `_secret`, `_mode`, `_count`, `_empty`"),
            (format!(r#"{{"_empty": {{{quoted}: 1}}}}"#), "unknown field: this object takes no fields"),
            (r#"{"_count": 70000}"#.to_owned(), "invalid value: integer, expected u8"),
        ];
        for (request, says) in &cases {
            // Decoded both ways the host decodes: from bytes at the edge, from a value in the core.
            let from_bytes = decode_error(&serde_json::from_str::<Request>(request).unwrap_err());
            let value: serde_json::Value = serde_json::from_str(request).unwrap();
            let from_value = decode_error(&serde_json::from_value::<Request>(value).unwrap_err());
            for message in [&from_bytes, &from_value] {
                assert!(message.starts_with(says), "{request}: `{message}` should start with `{says}`");
                for fragment in ["hunter2", "anything", "70000"] {
                    assert!(!message.contains(fragment), "{request}: `{message}` repeats the request");
                }
            }
            assert!(from_bytes.contains(" at line 1 column "), "where the error is stays in the message: {from_bytes}");
        }
        // What this crate's own validators and the JSON syntax say is kept as it is.
        let own = serde_json::from_str::<crate::ids::SandboxId>(&quoted).unwrap_err();
        assert!(decode_error(&own).contains("invalid SandboxId: expected `sbx-` followed by"), "{}", decode_error(&own));
        assert!(!decode_error(&own).contains("hunter2"));
        let syntax = serde_json::from_str::<Request>("{").unwrap_err();
        assert_eq!(decode_error(&syntax), syntax.to_string());
    }

    #[test]
    fn deferred_features_are_not_advertised() {
        assert!(!FEATURES.contains(&"signed_decision"));
        assert!(!FEATURES.contains(&"incremental_output"));
        let mut sorted = FEATURES.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, FEATURES, "kept sorted so the advertised list is stable");
    }
}
