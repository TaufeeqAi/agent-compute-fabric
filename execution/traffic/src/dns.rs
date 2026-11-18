//! A strict, minimal DNS wire codec: read one question from a guest, answer it with IPv4 address records.
//!
//! The parser accepts exactly one shape of message - a standard query with a single uncompressed question,
//! optionally followed by one EDNS OPT record that is ignored - and refuses everything else. It never follows
//! a compression pointer, never allocates more than one name's worth of bytes and cannot panic on any input
//! (property-tested below). The builder emits `A` records only (AL-3) and its output never exceeds 512 bytes.

use std::net::Ipv4Addr;

use crate::policy::{DnsName, MAX_LABEL_LEN, MAX_NAME_LEN};
use crate::reader::Reader;

pub const HEADER_LEN: usize = 12;
/// Largest datagram read from a guest and largest response ever built: the classic UDP limit (EDNS is not offered).
pub const MAX_MESSAGE_LEN: usize = 512;
/// Most address records in one response. With the longest question this still fits in [`MAX_MESSAGE_LEN`].
pub const MAX_ANSWERS: usize = 8;
pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;

const CLASS_IN: u16 = 1;
const TYPE_OPT: u16 = 41;
const FLAG_QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
/// Longest question: a 255-byte wire name, the type and the class.
const MAX_QUESTION_LEN: usize = MAX_NAME_LEN + 2 + 4;
/// One answer: a pointer to the question name, type, class, TTL, data length and four address bytes.
const A_RECORD_LEN: usize = 16;
/// Compression pointer to offset 12, where the question name starts.
const QUESTION_NAME_POINTER: u16 = 0xC00C;

const _: () = assert!(HEADER_LEN + MAX_QUESTION_LEN + MAX_ANSWERS * A_RECORD_LEN <= MAX_MESSAGE_LEN);

/// The response codes this resolver uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NotImp = 4,
    Refused = 5,
}

/// A query the resolver can answer or refuse with the question echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub recursion_desired: bool,
    /// `None` when the question is well formed on the wire but can never be on an allowlist: it is not class
    /// IN or its name is not a host name (AL-1). Such a query is refused like any unlisted name (AL-3).
    pub name: Option<DnsName>,
    pub qtype: u16,
    /// The question section exactly as the guest sent it; it is echoed verbatim, letter case included.
    question: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("datagram is shorter than a DNS header")]
    TooShort,
    #[error("message is a response, not a query")]
    NotAQuery,
    #[error("opcode is not QUERY")]
    NotImplemented { id: u16, flags: u16 },
    #[error("malformed query: {reason}")]
    Malformed { id: u16, flags: u16, reason: &'static str },
}

impl DnsError {
    /// The header-only response this input deserves: NOTIMP or FORMERR carrying the query id. `None` when the
    /// input has no usable header or is itself a response, which is never answered.
    pub fn response(&self) -> Option<Vec<u8>> {
        let (id, flags, rcode) = match *self {
            Self::TooShort | Self::NotAQuery => return None,
            Self::NotImplemented { id, flags } => (id, flags, Rcode::NotImp),
            Self::Malformed { id, flags, .. } => (id, flags, Rcode::FormErr),
        };
        let mut out = Vec::with_capacity(HEADER_LEN);
        put_u16(&mut out, id);
        put_u16(&mut out, FLAG_QR | (flags & (OPCODE_MASK | FLAG_RD)) | rcode as u16);
        out.resize(HEADER_LEN, 0);
        Some(out)
    }
}

/// Parses one datagram received from the guest.
pub fn parse_query(packet: &[u8]) -> Result<Query, DnsError> {
    let mut reader = Reader::new(packet);
    let Some([id, flags, questions, answers, authorities, additionals]) = read_header(&mut reader) else { return Err(DnsError::TooShort) };
    if flags & FLAG_QR != 0 {
        return Err(DnsError::NotAQuery);
    }
    if flags & OPCODE_MASK != 0 {
        return Err(DnsError::NotImplemented { id, flags });
    }
    let malformed = |reason| DnsError::Malformed { id, flags, reason };
    if flags & FLAG_TC != 0 {
        return Err(malformed("the query is marked truncated"));
    }
    if questions != 1 {
        return Err(malformed("exactly one question is required"));
    }
    if answers != 0 || authorities != 0 || additionals > 1 {
        return Err(malformed("only one additional record may follow the question"));
    }

    let name = read_name(&mut reader).map_err(malformed)?;
    let (Some(qtype), Some(qclass)) = (reader.u16(), reader.u16()) else { return Err(malformed("the question is cut short")) };
    let question_end = packet.len() - reader.remaining();
    let question = packet.get(HEADER_LEN..question_end).ok_or(malformed("the question is cut short"))?.to_vec();

    if additionals == 1 {
        skip_opt(&mut reader).ok_or(malformed("the additional record is not a well-formed OPT record"))?;
    }
    if !reader.is_empty() {
        return Err(malformed("bytes follow the last record"));
    }
    let name = name.filter(|_| qclass == CLASS_IN);
    Ok(Query { id, recursion_desired: flags & FLAG_RD != 0, name, qtype, question })
}

/// The six header words: id, flags and the four section counts.
fn read_header(reader: &mut Reader<'_>) -> Option<[u16; 6]> {
    Some([reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?])
}

/// Reads an uncompressed name. `Ok(None)` is a name that is well formed on the wire but is not a host name:
/// the root, a single label, or a label with a byte outside letters, digits and the hyphen.
fn read_name(reader: &mut Reader<'_>) -> Result<Option<DnsName>, &'static str> {
    let mut text = String::new();
    let mut host_name = true;
    // Presentation length plus one: every label counts its bytes and one separator.
    let mut length = 0usize;
    loop {
        let len = reader.u8().ok_or("the question name is cut short")?;
        if len == 0 {
            break;
        }
        // A length byte above 63 is a compression pointer or a reserved label type.
        if usize::from(len) > MAX_LABEL_LEN {
            return Err("the question name uses compression or a reserved label type");
        }
        let label = reader.take(usize::from(len)).ok_or("the question name is cut short")?;
        length += label.len() + 1;
        if length > MAX_NAME_LEN + 1 {
            return Err("the question name is longer than 253 bytes");
        }
        // A label holding a dot or any other non-LDH byte must not be flattened into dotted text.
        if !label.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
            host_name = false;
        }
        if host_name {
            if !text.is_empty() {
                text.push('.');
            }
            text.extend(label.iter().map(|b| char::from(*b)));
        }
    }
    Ok(if host_name { DnsName::parse(&text).ok() } else { None })
}

/// EDNS: one OPT pseudo-record (root owner name, type 41) is tolerated and ignored.
fn skip_opt(reader: &mut Reader<'_>) -> Option<()> {
    let owner = reader.u8()?;
    let rtype = reader.u16()?;
    let _udp_payload_size = reader.u16()?;
    let _extended_flags = reader.take(4)?;
    let _options = reader.vec16()?;
    (owner == 0 && rtype == TYPE_OPT).then_some(())
}

/// Builds the response to `query`. Address records are emitted only for a NOERROR answer to an `A` question
/// (AL-3: address records only), at most [`MAX_ANSWERS`] of them, each named by a pointer to the question.
pub fn build_response(query: &Query, rcode: Rcode, answers: &[Ipv4Addr], ttl_secs: u32) -> Vec<u8> {
    let count = if rcode == Rcode::NoError && query.qtype == QTYPE_A { answers.len().min(MAX_ANSWERS) } else { 0 };
    let recursion = if query.recursion_desired { FLAG_RD } else { 0 };
    let mut out = Vec::with_capacity(HEADER_LEN + query.question.len() + count * A_RECORD_LEN);
    put_u16(&mut out, query.id);
    put_u16(&mut out, FLAG_QR | FLAG_RA | recursion | rcode as u16);
    put_u16(&mut out, 1);
    put_u16(&mut out, count as u16);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    out.extend_from_slice(&query.question);
    for addr in answers.iter().take(count) {
        put_u16(&mut out, QUESTION_NAME_POINTER);
        put_u16(&mut out, QTYPE_A);
        put_u16(&mut out, CLASS_IN);
        out.extend_from_slice(&ttl_secs.to_be_bytes());
        put_u16(&mut out, 4);
        out.extend_from_slice(&addr.octets());
    }
    out
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const RD: u16 = FLAG_RD;

    /// A raw message: header with the given flags and counts, then `body` verbatim.
    fn message(id: u16, flags: u16, counts: [u16; 4], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for word in [id, flags, counts[0], counts[1], counts[2], counts[3]] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn question(labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
        out
    }

    fn query(labels: &[&[u8]], qtype: u16) -> Vec<u8> {
        message(0x1234, RD, [1, 0, 0, 0], &question(labels, qtype, CLASS_IN))
    }

    fn opt(rdata: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0];
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn malformed_reason(packet: &[u8]) -> &'static str {
        match parse_query(packet) {
            Err(DnsError::Malformed { id: 0x1234, reason, .. }) => reason,
            other => panic!("expected a malformed query, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_plain_query_and_normalises_the_name() {
        let packet = query(&[b"WwW", b"Example", b"COM"], QTYPE_A);
        let parsed = parse_query(&packet).unwrap();
        assert_eq!((parsed.id, parsed.recursion_desired, parsed.qtype), (0x1234, true, QTYPE_A));
        assert_eq!(parsed.name.as_ref().map(DnsName::as_str), Some("www.example.com"));
        assert_eq!(parsed.question, &packet[HEADER_LEN..]);

        let no_recursion = message(7, 0, [1, 0, 0, 0], &question(&[b"example", b"com"], QTYPE_AAAA, CLASS_IN));
        let parsed = parse_query(&no_recursion).unwrap();
        assert_eq!((parsed.id, parsed.recursion_desired, parsed.qtype), (7, false, QTYPE_AAAA));
    }

    #[test]
    fn tolerates_and_ignores_one_opt_record() {
        for rdata in [&[][..], &[0, 10, 0, 2, 0xab, 0xcd][..]] {
            let mut body = question(&[b"example", b"com"], QTYPE_A, CLASS_IN);
            let question_len = body.len();
            body.extend_from_slice(&opt(rdata));
            // The AD and CD bits that modern stub resolvers set are ignored too.
            let packet = message(0x1234, RD | 0x0030, [1, 0, 0, 1], &body);
            let parsed = parse_query(&packet).unwrap();
            assert_eq!(parsed.name.as_ref().map(DnsName::as_str), Some("example.com"));
            assert_eq!(parsed.question.len(), question_len, "the OPT record is not echoed");
        }
    }

    #[test]
    fn well_formed_questions_that_are_not_host_names_carry_no_name() {
        let long_label = [b'a'; 63];
        let cases: [&[&[u8]]; 9] = [
            &[],
            &[b"localhost"],
            &[b"_dmarc", b"example", b"com"],
            &[b"a.b", b"com"],
            &[b"exa\0mple", b"com"],
            &[b"\xc3\xbc", b"example"],
            &[b"198", b"51", b"100", b"10"],
            &[b"-a", b"com"],
            &[&long_label, b"1x"],
        ];
        for labels in cases {
            let parsed = parse_query(&query(labels, QTYPE_A)).unwrap();
            assert_eq!(parsed.name, None, "{labels:?}");
        }
        // Not class IN (here CHAOS): the name is ignored, the question is still echoable.
        let chaos = message(0x1234, RD, [1, 0, 0, 0], &question(&[b"version", b"bind"], 16, 3));
        assert_eq!(parse_query(&chaos).unwrap().name, None);
    }

    #[test]
    fn name_length_limit_is_253_bytes() {
        let (a, b) = ([b'a'; 63], [b'b'; 61]);
        let longest = query(&[&a, &a, &a, &b], QTYPE_A);
        let name = parse_query(&longest).unwrap().name.unwrap();
        assert_eq!(name.as_str().len(), MAX_NAME_LEN);
        let too_long = query(&[&a, &a, &a, &b, b"c"], QTYPE_A);
        assert_eq!(malformed_reason(&too_long), "the question name is longer than 253 bytes");
        let just_over = query(&[&a, &a, &a, &[b'b'; 62]], QTYPE_A);
        assert_eq!(malformed_reason(&just_over), "the question name is longer than 253 bytes");
    }

    #[test]
    fn rejects_everything_else() {
        let good = question(&[b"example", b"com"], QTYPE_A, CLASS_IN);
        let with = |extra: &[u8]| [good.as_slice(), extra].concat();

        assert_eq!(parse_query(&[]), Err(DnsError::TooShort));
        assert_eq!(parse_query(&query(&[b"example", b"com"], QTYPE_A)[..HEADER_LEN - 1]), Err(DnsError::TooShort));
        assert_eq!(parse_query(&message(0x1234, FLAG_QR | RD, [1, 0, 0, 0], &good)), Err(DnsError::NotAQuery));
        for opcode in 1..=15u16 {
            let flags = (opcode << 11) | RD;
            assert_eq!(parse_query(&message(0x1234, flags, [1, 0, 0, 0], &good)), Err(DnsError::NotImplemented { id: 0x1234, flags }));
        }

        let one = "exactly one question is required";
        let sections = "only one additional record may follow the question";
        let name_cut = "the question name is cut short";
        let compressed = "the question name uses compression or a reserved label type";
        let question_cut = "the question is cut short";
        let trailing = "bytes follow the last record";
        let bad_opt = "the additional record is not a well-formed OPT record";
        let rows: Vec<(Vec<u8>, &str)> = vec![
            (message(0x1234, RD | FLAG_TC, [1, 0, 0, 0], &good), "the query is marked truncated"),
            (message(0x1234, RD, [0, 0, 0, 0], &[]), one),
            (message(0x1234, RD, [2, 0, 0, 0], &with(&good)), one),
            (message(0x1234, RD, [1, 1, 0, 0], &good), sections),
            (message(0x1234, RD, [1, 0, 1, 0], &good), sections),
            (message(0x1234, RD, [1, 0, 0, 2], &with(&[opt(&[]), opt(&[])].concat())), sections),
            (message(0x1234, RD, [1, 0, 0, 0], &[]), name_cut),
            (message(0x1234, RD, [1, 0, 0, 0], &[7, b'e', b'x']), name_cut),
            (message(0x1234, RD, [1, 0, 0, 0], &[3, b'c', b'o', b'm']), name_cut),
            (message(0x1234, RD, [1, 0, 0, 0], &[0xc0, 0x0c, 0, 1, 0, 1]), compressed),
            (message(0x1234, RD, [1, 0, 0, 0], &[3, b'w', b'w', b'w', 0xc0, 0x0c, 0, 1, 0, 1]), compressed),
            (message(0x1234, RD, [1, 0, 0, 0], &[0x40, 0, 0, 1, 0, 1]), compressed),
            (message(0x1234, RD, [1, 0, 0, 0], &[0x80, 0, 0, 1, 0, 1]), compressed),
            (message(0x1234, RD, [1, 0, 0, 0], &good[..good.len() - 1]), question_cut),
            (message(0x1234, RD, [1, 0, 0, 0], &good[..good.len() - 4]), question_cut),
            (message(0x1234, RD, [1, 0, 0, 0], &with(&[0])), trailing),
            (message(0x1234, RD, [1, 0, 0, 0], &with(&opt(&[]))), trailing),
            (message(0x1234, RD, [1, 0, 0, 1], &with(&[opt(&[]), vec![0]].concat())), trailing),
            (message(0x1234, RD, [1, 0, 0, 1], &good), bad_opt),
            (message(0x1234, RD, [1, 0, 0, 1], &with(&opt(&[])[..10])), bad_opt),
            (message(0x1234, RD, [1, 0, 0, 1], &with(&[0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 5, 1])), bad_opt),
            (message(0x1234, RD, [1, 0, 0, 1], &with(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0])), bad_opt),
            (message(0x1234, RD, [1, 0, 0, 1], &with(&[1, b'a', 0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0])), bad_opt),
        ];
        for (packet, reason) in rows {
            assert_eq!(malformed_reason(&packet), reason, "{packet:02x?}");
        }
    }

    #[test]
    fn error_responses_are_header_only() {
        let good = question(&[b"example", b"com"], QTYPE_A, CLASS_IN);
        assert_eq!(DnsError::TooShort.response(), None);
        assert_eq!(DnsError::NotAQuery.response(), None);

        let formerr = parse_query(&message(0xbeef, RD, [2, 0, 0, 0], &good)).unwrap_err().response().unwrap();
        assert_eq!(formerr, message(0xbeef, FLAG_QR | RD | 1, [0, 0, 0, 0], &[]));
        // NOTIMP echoes the opcode (here 2, STATUS) and the id; the recursion bit was not set and stays clear.
        let notimp = parse_query(&message(0xbeef, 2 << 11, [1, 0, 0, 0], &good)).unwrap_err().response().unwrap();
        assert_eq!(notimp, message(0xbeef, FLAG_QR | (2 << 11) | 4, [0, 0, 0, 0], &[]));
    }

    #[test]
    fn builds_answers_with_the_question_echoed() {
        let packet = query(&[b"Example", b"COM"], QTYPE_A);
        let parsed = parse_query(&packet).unwrap();
        let addrs = [Ipv4Addr::new(198, 51, 100, 10), Ipv4Addr::new(203, 0, 113, 7)];
        let response = build_response(&parsed, Rcode::NoError, &addrs, 60);

        let mut expected = message(0x1234, FLAG_QR | RD | FLAG_RA, [1, 2, 0, 0], &packet[HEADER_LEN..]);
        for addr in addrs {
            expected.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            expected.extend_from_slice(&addr.octets());
        }
        assert_eq!(response, expected);
    }

    #[test]
    fn builds_empty_and_error_responses() {
        let packet = query(&[b"example", b"com"], QTYPE_A);
        let parsed = parse_query(&packet).unwrap();
        let addrs = [Ipv4Addr::new(198, 51, 100, 10)];
        for (rcode, code) in [(Rcode::Refused, 5), (Rcode::ServFail, 2), (Rcode::FormErr, 1), (Rcode::NotImp, 4)] {
            let response = build_response(&parsed, rcode, &addrs, 60);
            assert_eq!(response, message(0x1234, FLAG_QR | RD | FLAG_RA | code, [1, 0, 0, 0], &packet[HEADER_LEN..]), "{rcode:?}");
        }
        assert_eq!(
            build_response(&parsed, Rcode::NoError, &[], 60),
            message(0x1234, FLAG_QR | RD | FLAG_RA, [1, 0, 0, 0], &packet[HEADER_LEN..])
        );

        // AL-3: address records answer an A question and nothing else.
        let aaaa = query(&[b"example", b"com"], QTYPE_AAAA);
        let parsed = parse_query(&aaaa).unwrap();
        assert_eq!(
            build_response(&parsed, Rcode::NoError, &addrs, 60),
            message(0x1234, FLAG_QR | RD | FLAG_RA, [1, 0, 0, 0], &aaaa[HEADER_LEN..])
        );
    }

    #[test]
    fn the_largest_response_fits_in_512_bytes() {
        let (a, b) = ([b'a'; 63], [b'b'; 61]);
        let parsed = parse_query(&query(&[&a, &a, &a, &b], QTYPE_A)).unwrap();
        let many: Vec<Ipv4Addr> = (0..40).map(|n| Ipv4Addr::new(198, 51, 100, n)).collect();
        let response = build_response(&parsed, Rcode::NoError, &many, u32::MAX);
        assert_eq!(response.len(), HEADER_LEN + MAX_QUESTION_LEN + MAX_ANSWERS * A_RECORD_LEN);
        assert!(response.len() <= MAX_MESSAGE_LEN);
        assert_eq!(&response[6..8], &(MAX_ANSWERS as u16).to_be_bytes(), "the answer count matches the records emitted");
    }

    fn check_parse(packet: &[u8]) -> Result<(), TestCaseError> {
        match parse_query(packet) {
            Ok(parsed) => {
                if let Some(name) = &parsed.name {
                    let reparsed = DnsName::parse(name.as_str());
                    prop_assert_eq!(reparsed.as_ref(), Ok(name));
                }
                prop_assert!(parsed.question.len() <= MAX_QUESTION_LEN);
                let response = build_response(&parsed, Rcode::NoError, &[Ipv4Addr::new(198, 51, 100, 1); 32], 60);
                prop_assert!(response.len() <= MAX_MESSAGE_LEN);
                prop_assert_eq!(&response[..2], &packet[..2]);
            }
            Err(error) => {
                if let Some(response) = error.response() {
                    prop_assert_eq!(response.len(), HEADER_LEN);
                    prop_assert_eq!(&response[..2], &packet[..2]);
                    prop_assert!(response[2] & 0x80 != 0, "the response bit is set");
                    prop_assert!(response[4..].iter().all(|b| *b == 0), "nothing is echoed");
                }
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(packet in prop::collection::vec(any::<u8>(), 0..600)) {
            check_parse(&packet)?;
        }

        /// Mutations of a valid query reach much deeper into the parser than random bytes do.
        #[test]
        fn mutated_queries_never_panic(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
            cut in any::<prop::sample::Index>(),
            truncate in any::<bool>(),
        ) {
            let mut body = question(&[b"www", b"example", b"com"], QTYPE_A, CLASS_IN);
            body.extend_from_slice(&opt(&[0, 10, 0, 2, 0xab, 0xcd]));
            let mut packet = message(0x1234, RD, [1, 0, 0, 1], &body);
            for (at, byte) in edits {
                let at = at.index(packet.len());
                packet[at] = byte;
            }
            if truncate {
                packet.truncate(cut.index(packet.len() + 1));
            }
            check_parse(&packet)?;
        }
    }
}
