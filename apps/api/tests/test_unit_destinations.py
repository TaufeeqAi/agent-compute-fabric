"""The destination relation: when a requested allowlist entry is inside what a grant allows.

Proves AZ-8, clause by clause: a name equals a granted name as ASCII lower case after conversion to
A-labels and removal of a trailing dot, or lies under a granted suffix rule at a label boundary; a
network is contained in a granted network; in either case the requested ports are a subset of the
ports granted for that destination; a name is never matched against a network, nor a network against
a name; and anything else is denied. Catalog entry: T3-RED-11 (a set of confusable names, and a
reference matcher over random pairs with identical verdicts).

Two readings the clause leaves open are fixed here, and reported:

* "the ports granted for that destination" are the ports of the one granted entry that admits the
  request. Two entries of a grant for the same name do not add up their ports, and two networks do not
  add up to their union. A caller who needs both asks for two entries.
* the conversion to A-labels is the one of the standard library (IDNA 2003, RFC 3490). It folds
  compatibility spellings of an ASCII name onto that name. The host accepts ASCII names only, so a
  spelling that is not ASCII is refused there whatever the platform decided.

The reference matcher below is written from the clause in the most naive way that works: sets of port
numbers, lists of labels, pairs of first and last address. It shares no code with the implementation,
and converts the few non-ASCII labels it meets from a table of known A-labels.
"""

from __future__ import annotations

import functools
import itertools
from collections import Counter
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from acf_api.core.policy import destinations as d
from acf_api.core.policy.destinations import (
    Destination,
    destination,
    inside,
    normalize_name,
    normalize_network,
    normalize_ports,
)

HTTPS = ((443, 443),)
Raw = tuple[str, str, tuple[tuple[int, int], ...]]


def dest(
    *, name: str | None = None, suffix: str | None = None, network: str | None = None, ports: Any = HTTPS
) -> Destination | None:
    return destination(name=name, suffix=suffix, network=network, ports=list(ports))


def grant(*entries: Destination | None) -> tuple[Destination, ...]:
    """A grant's destinations. A grant holds no entry that cannot be read: such a grant is unusable as a whole."""
    out = []
    for entry in entries:
        assert entry is not None, "a test built a grant from a malformed entry"
        out.append(entry)
    return tuple(out)


def admits(granted: tuple[Destination, ...], requested: Destination | None) -> bool:
    """The verdict as the access policy takes it: an entry that cannot be read is inside nothing."""
    return requested is not None and inside(requested, granted)


EXAMPLE = grant(dest(name="example.com"))


# ------------------------------------------------------------------------------- names
@pytest.mark.proves("T3-RED-11")
def test_a_name_is_inside_only_the_same_name() -> None:
    assert admits(EXAMPLE, dest(name="example.com"))
    for other in (
        "example.org",
        "example.co",
        "example.comm",
        "xample.com",
        "www.example.com",
        "com",
        "example",
        "example.com.com",
    ):
        assert not admits(EXAMPLE, dest(name=other)), other
    assert not admits((), dest(name="example.com"))


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize("spelling", ["EXAMPLE.COM", "Example.Com", "eXaMpLe.cOm", "example.COM"])
def test_case_does_not_tell_two_names_apart(spelling: str) -> None:
    assert admits(EXAMPLE, dest(name=spelling))
    assert admits(grant(dest(name=spelling)), dest(name="example.com"))
    assert dest(name=spelling) == dest(name="example.com")


@pytest.mark.proves("T3-RED-11")
def test_one_trailing_dot_is_removed_and_two_are_not_a_name() -> None:
    assert admits(EXAMPLE, dest(name="example.com."))
    assert admits(grant(dest(name="example.com.")), dest(name="example.com"))
    assert admits(grant(dest(name="EXAMPLE.com.")), dest(name="example.COM."))
    assert dest(name="example.com..") is None
    assert dest(name=".") is None
    assert dest(name="com.") == dest(name="com")


#: A spelling and the A-label form it has. Known conversions, not computed here.
A_LABELS = [
    ("b\u00fccher.example", "xn--bcher-kva.example"),
    ("B\u00dcCHER.EXAMPLE", "xn--bcher-kva.example"),
    ("m\u00fcnchen.de", "xn--mnchen-3ya.de"),
    ("\u4f8b\u3048.jp", "xn--r8jz45g.jp"),
    ("\u043f\u0440\u0438\u043c\u0435\u0440.example", "xn--e1afmkfd.example"),
    ("\u4e2d\u6587.example", "xn--fiq228c.example"),
    ("espa\u00f1ol.example", "xn--espaol-zwa.example"),
    ("shop.b\u00fccher.example.", "shop.xn--bcher-kva.example"),
    ("XN--BCHER-KVA.Example", "xn--bcher-kva.example"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
]


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(("spelling", "a_label_form"), A_LABELS)
def test_a_name_is_compared_in_its_a_label_form(spelling: str, a_label_form: str) -> None:
    assert normalize_name(spelling) == a_label_form
    assert admits(grant(dest(name=a_label_form)), dest(name=spelling))
    assert admits(grant(dest(name=spelling)), dest(name=a_label_form))
    assert not admits(EXAMPLE, dest(name=spelling))


# ------------------------------------------------------------------------------- suffix rules
UNDER_EXAMPLE = grant(dest(suffix="*.example.com"))


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "name",
    [
        "a.example.com",
        "www.example.com",
        "a.b.example.com",
        "A.Example.COM",
        "a.example.com.",
        "example.com.example.com",
        "x-1.example.com",
    ],
)
def test_a_name_under_a_suffix_rule_is_inside(name: str) -> None:
    assert admits(UNDER_EXAMPLE, dest(name=name))


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "example.com.",
        "evilexample.com",
        "xexample.com",
        "-example.com",
        "a.evilexample.com",
        "example.com.evil.org",
        "a.example.com.evil.org",
        "a.example.co",
        "a.example.comm",
        "a.example.org",
        "aexample.com",
        "com",
        "a.com",
        "a.example",
    ],
)
def test_a_suffix_rule_holds_at_a_label_boundary_only(name: str) -> None:
    """`evilexample.com` ends with the letters of the suffix and is another domain. The suffix itself is not under itself."""
    assert not admits(UNDER_EXAMPLE, dest(name=name))


@pytest.mark.proves("T3-RED-11")
def test_a_suffix_rule_is_compared_like_a_name() -> None:
    assert admits(grant(dest(suffix="*.EXAMPLE.com.")), dest(name="a.example.COM"))
    assert admits(grant(dest(suffix="*.b\u00fccher.example")), dest(name="shop.xn--bcher-kva.example"))
    assert admits(grant(dest(suffix="*.xn--bcher-kva.example")), dest(name="shop.B\u00dcCHER.example"))
    assert not admits(grant(dest(suffix="*.b\u00fccher.example")), dest(name="shop.bucher.example"))
    assert admits(grant(dest(suffix="*.com")), dest(name="example.com"))
    assert not admits(grant(dest(suffix="*.com")), dest(name="com"))


@pytest.mark.proves("T3-RED-11")
def test_a_granted_name_admits_no_name_under_it() -> None:
    for name in ("a.example.com", "www.example.com", "a.b.example.com"):
        assert not admits(EXAMPLE, dest(name=name)), name


@pytest.mark.proves("T3-RED-11")
def test_a_suffix_rule_is_inside_a_suffix_rule_that_covers_it() -> None:
    """Narrowing: a credential may hold a suffix rule only if its parent's grant covers every name under it."""
    assert admits(UNDER_EXAMPLE, dest(suffix="*.example.com"))
    assert admits(UNDER_EXAMPLE, dest(suffix="*.a.example.com"))
    assert admits(UNDER_EXAMPLE, dest(suffix="*.A.b.EXAMPLE.com."))
    for wider in ("*.com", "*.evilexample.com", "*.example.org", "*.xample.com"):
        assert not admits(UNDER_EXAMPLE, dest(suffix=wider)), wider
    assert not admits(grant(dest(suffix="*.a.example.com")), dest(suffix="*.example.com"))
    # A name admits one name. It covers no rule, not even the rule of the names under itself.
    assert not admits(EXAMPLE, dest(suffix="*.example.com"))
    assert not admits(grant(dest(network="0.0.0.0/0")), dest(suffix="*.example.com"))


# ------------------------------------------------------------------------------- networks
TEN = grant(dest(network="10.0.0.0/8"))


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "network",
    ["10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9", "10.1.2.0/24", "10.255.255.255/32", "10.0.0.0/32", "10.20.0.0/16"],
)
def test_a_network_contained_in_a_granted_network_is_inside(network: str) -> None:
    assert admits(TEN, dest(network=network))


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "network",
    [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "8.0.0.0/6",
        "11.0.0.0/8",
        "9.255.255.255/32",
        "11.0.0.0/32",
        "192.168.0.0/16",
        "0.0.0.0/32",
    ],
)
def test_a_network_that_reaches_outside_a_granted_network_is_not_inside(network: str) -> None:
    assert not admits(TEN, dest(network=network))


@pytest.mark.proves("T3-RED-11")
def test_containment_is_judged_against_one_granted_network_at_a_time() -> None:
    halves = grant(dest(network="10.0.0.0/25"), dest(network="10.0.0.128/25"))
    assert admits(halves, dest(network="10.0.0.0/25"))
    assert admits(halves, dest(network="10.0.0.128/26"))
    assert not admits(halves, dest(network="10.0.0.0/24"))
    everything = grant(dest(network="0.0.0.0/0", ports=((1, 65535),)))
    assert admits(everything, dest(network="203.0.113.7/32", ports=((1, 65535),)))
    assert admits(grant(dest(network="203.0.113.7/32")), dest(network="203.0.113.7/32"))
    assert not admits(grant(dest(network="203.0.113.7/32")), dest(network="203.0.113.6/31"))


@pytest.mark.proves("T3-RED-11")
def test_a_name_is_never_matched_against_a_network_nor_a_network_against_a_name() -> None:
    everything = grant(dest(network="0.0.0.0/0", ports=((1, 65535),)))
    for name in ("example.com", "10.0.0.1", "10.in-addr.arpa", "localhost"):
        assert not admits(everything, dest(name=name)), name
    names = grant(dest(name="10.0.0.1"), dest(name="example.com"), dest(suffix="*.0.1"), dest(suffix="*.com"))
    for network in ("10.0.0.1/32", "10.0.0.0/8", "0.0.0.0/0"):
        assert not admits(names, dest(network=network)), network
    # Each form is told apart by the member it arrives in, never by what the text looks like.
    assert dest(name="10.0.0.0/8") is None
    assert dest(network="example.com") is None
    assert dest(suffix="*.10.0.0.0/8") is None


# ------------------------------------------------------------------------------- ports
@pytest.mark.proves("T3-RED-11")
def test_requested_ports_must_be_a_subset_of_the_granted_ports() -> None:
    web = grant(dest(name="example.com", ports=((80, 80), (443, 443))))
    assert admits(web, dest(name="example.com", ports=((443, 443),)))
    assert admits(web, dest(name="example.com", ports=((80, 80),)))
    assert admits(web, dest(name="example.com", ports=((443, 443), (80, 80))))
    for more in (((22, 22),), ((80, 81),), ((79, 80),), ((80, 443),), ((443, 443), (8443, 8443)), ((1, 65535),)):
        assert not admits(web, dest(name="example.com", ports=more)), more


@pytest.mark.proves("T3-RED-11")
def test_adjacent_and_overlapping_ranges_are_one_range_and_a_gap_stays_a_gap() -> None:
    merged = grant(dest(name="example.com", ports=((80, 85), (86, 90))))
    assert admits(merged, dest(name="example.com", ports=((80, 90),)))
    assert admits(merged, dest(name="example.com", ports=((84, 87),)))
    overlapping = grant(dest(name="example.com", ports=((86, 90), (80, 87), (82, 83))))
    assert admits(overlapping, dest(name="example.com", ports=((80, 90),)))
    assert normalize_ports([(86, 90), (80, 87), (82, 83)]) == ((80, 90),)

    split = grant(dest(name="example.com", ports=((80, 84), (86, 90))))
    assert not admits(split, dest(name="example.com", ports=((80, 90),)))
    assert not admits(split, dest(name="example.com", ports=((84, 86),)))
    assert not admits(split, dest(name="example.com", ports=((85, 85),)))
    assert admits(split, dest(name="example.com", ports=((80, 84), (86, 90))))
    assert admits(split, dest(name="example.com", ports=((80, 80), (90, 90), (82, 83))))
    # The request may be split where the grant is whole, and whole where the grant only looks split.
    assert admits(merged, dest(name="example.com", ports=((80, 82), (83, 83), (84, 90))))
    assert normalize_ports([(80, 84), (86, 90)]) == ((80, 84), (86, 90))


@pytest.mark.proves("T3-RED-11")
def test_ports_are_judged_with_the_destination_that_admits_the_request() -> None:
    """The ports of another destination of the grant never help. Each entry of a grant stands for itself."""
    mixed = grant(
        dest(name="example.com", ports=((443, 443),)),
        dest(name="example.org", ports=((22, 22),)),
        dest(suffix="*.example.com", ports=((8443, 8443),)),
        dest(network="10.0.0.0/8", ports=((5432, 5432),)),
    )
    assert not admits(mixed, dest(name="example.com", ports=((22, 22),)))
    assert not admits(mixed, dest(name="example.com", ports=((8443, 8443),)))
    assert not admits(mixed, dest(name="a.example.com", ports=((443, 443),)))
    assert not admits(mixed, dest(network="10.1.0.0/16", ports=((443, 443),)))
    assert admits(mixed, dest(name="a.example.com", ports=((8443, 8443),)))
    assert admits(mixed, dest(network="10.1.0.0/16", ports=((5432, 5432),)))
    twice = grant(dest(name="example.com", ports=((80, 80),)), dest(name="example.com", ports=((443, 443),)))
    assert admits(twice, dest(name="example.com", ports=((80, 80),)))
    assert admits(twice, dest(name="example.com", ports=((443, 443),)))
    assert not admits(twice, dest(name="example.com", ports=((80, 80), (443, 443))))


# ------------------------------------------------------------------------------- malformed entries
LONGEST_LABEL = "a" * 63
#: 253 characters: the longest name there is.
LONGEST_NAME = ".".join([LONGEST_LABEL, LONGEST_LABEL, LONGEST_LABEL, "a" * 61])


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        ".example.com",
        "example..com",
        "example.com..",
        "exam ple.com",
        " example.com",
        "example.com ",
        "example.com\n",
        "example.com\x00",
        "exam\tple.com",
        "exam_ple.com",
        "*.example.com",
        "*",
        "example.com:443",
        "example.com/",
        "http://example.com",
        "user@example.com",
        "example.com#x",
        "example.com\\x",
        "-example.com",
        "example-.com",
        "example.-com",
        "a" * 64 + ".com",
        "example." + "a" * 64,
        LONGEST_NAME + "a",
        LONGEST_NAME + ".a",
        "a." * 127 + "a",
        "xn--.com",
        "example\u3002com",
        "example\uff0ecom",
        "example\uff61com",
        "example.com\u2024",
        "\u00fc" * 60 + ".example",
    ],
)
def test_a_malformed_name_is_inside_nothing(name: str) -> None:
    assert normalize_name(name) is None
    assert dest(name=name) is None
    assert dest(suffix="*." + name) is None
    assert not admits(grant(dest(suffix="*.com"), dest(name="example.com"), dest(network="0.0.0.0/0")), dest(name=name))


@pytest.mark.proves("T3-RED-11")
def test_the_bounds_of_a_name_are_those_of_its_a_label_form() -> None:
    assert len(LONGEST_NAME) == 253
    assert normalize_name(LONGEST_NAME) == LONGEST_NAME
    assert normalize_name(LONGEST_NAME + ".") == LONGEST_NAME
    assert normalize_name(LONGEST_LABEL + ".com") == LONGEST_LABEL + ".com"
    # Thirty letters with an umlaut are 36 characters as an A-label. Seven such labels are 216
    # characters as written and 258 as the resolver would see them: not a name.
    label = "\u00fc" * 30
    assert len(label.encode("idna")) == 36
    six, seven = ".".join([label] * 6), ".".join([label] * 7)
    assert len(seven) == 216
    assert len(seven) < d.MAX_NAME_LEN
    normalized = normalize_name(six)
    assert normalized is not None
    assert len(normalized) == 221
    assert normalize_name(seven) is None
    assert dest(name=seven) is None
    assert dest(suffix="*." + seven) is None


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "suffix",
    [
        "example.com",
        ".example.com",
        "*example.com",
        "**.example.com",
        "*.*.example.com",
        "*.",
        "*",
        "",
        "*..com",
        "*.example.com.*",
        "a.*.example.com",
        "x*.example.com",
        "*.exa mple.com",
    ],
)
def test_a_malformed_suffix_rule_is_inside_nothing(suffix: str) -> None:
    assert dest(suffix=suffix) is None


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "network",
    [
        "",
        "10.0.0.1/8",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "300.0.0.0/8",
        "10.0.0/8",
        "10.0.0.0.0/8",
        "10.0.0.0/8/8",
        "10.0.0.0/",
        "/8",
        "10.0.0.0/8 ",
        " 10.0.0.0/8",
        "10.0.0.0/8\n",
        "010.0.0.0/8",
        "0x0a.0.0.0/8",
        "10.0.0.0/+8",
        "10.0.0.0/8.0",
        "::/0",
        "::ffff:10.0.0.0/104",
        "example.com",
        "10.0.0.0/\u0668",
        "\u0661\u0660.0.0.0/8",
        # Notations the standard library reads and the host's entry form does not have.
        "10.0.0.10",
        "10.0.0.0/08",
        "10.0.0.0/008",
        "1.0.0.0/255.0.0.0",
        "10.0.0.0/0.0.0.255",
        "10.0.0.0/255.255.255.0",
    ],
)
def test_a_malformed_network_is_inside_nothing(network: str) -> None:
    assert normalize_network(network) is None
    assert dest(network=network) is None
    assert not admits(grant(dest(network="0.0.0.0/0", ports=((1, 65535),))), dest(network=network))


@pytest.mark.proves("T3-RED-11")
def test_a_network_is_written_in_one_form() -> None:
    for network in ("0.0.0.0/0", "10.0.0.0/8", "192.168.1.0/24", "203.0.113.7/32", "255.255.255.255/32", "128.0.0.0/1"):
        assert normalize_network(network) == network


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(
    "ports",
    [
        [],
        [(0, 80)],
        [(0, 0)],
        [(80, 65536)],
        [(65536, 65536)],
        [(-1, 80)],
        [(90, 80)],
        [(80, 80), (0, 1)],
        [(443, 443), (90, 80)],
        [(True, True)],
        [(80.0, 80.0)],
        [("80", "80")],
        [(None, 80)],
        [(80, None)],
        [(None, None)],
    ],
)
def test_a_malformed_port_set_is_inside_nothing(ports: Any) -> None:
    """Whatever stands where a port should be. A view of the host is read with the same function as a request."""
    assert normalize_ports(ports) is None
    assert dest(name="example.com", ports=ports) is None
    assert dest(network="10.0.0.0/8", ports=ports) is None
    assert dest(suffix="*.example.com", ports=ports) is None


@pytest.mark.proves("T3-RED-11")
def test_the_whole_range_of_ports_is_a_port_set() -> None:
    assert normalize_ports([(1, 65535)]) == ((1, 65535),)
    assert normalize_ports([(1, 1), (65535, 65535)]) == ((1, 1), (65535, 65535))
    assert normalize_ports([(1, 100), (101, 65535)]) == ((1, 65535),)


@pytest.mark.proves("T3-RED-11")
def test_an_entry_names_exactly_one_destination() -> None:
    assert destination(name=None, suffix=None, network=None, ports=[(443, 443)]) is None
    assert dest(name="example.com") == Destination("name", "example.com", HTTPS)
    assert dest(suffix="*.Example.com") == Destination("suffix", "example.com", HTTPS)
    assert dest(network="10.0.0.0/8") == Destination("network", "10.0.0.0/8", HTTPS)
    assert d.MAX_NAME_LEN == 253
    assert d.MAX_LABEL_LEN == 63


# ------------------------------------------------------------------------------- confusable names
#: A spelling, and the name it is in A-label form: ``None`` when it is no name at all. A spelling is
#: inside a grant for `example.com` exactly when that form is `example.com`.
CONFUSABLES: list[tuple[str, str | None]] = [
    # The name itself, as it may be written.
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("ExAmPlE.cOm", "example.com"),
    ("example.com.", "example.com"),
    ("EXAMPLE.COM.", "example.com"),
    # Dots where none belong: no name at all.
    ("example.com..", None),
    (".example.com", None),
    ("..example.com", None),
    ("example..com", None),
    ("example.com...", None),
    # ASCII look-alikes: other names.
    ("examp1e.com", "examp1e.com"),
    ("exarnple.com", "exarnple.com"),
    ("example.co", "example.co"),
    ("example.comm", "example.comm"),
    ("example.com.com", "example.com.com"),
    ("example-com", "example-com"),
    ("examplecom", "examplecom"),
    ("example.c0m", "example.c0m"),
    ("exampie.com", "exampie.com"),
    ("example.com.evil.org", "example.com.evil.org"),
    ("evil.org.example.com", "evil.org.example.com"),
    # Letters of other scripts that look like the Latin ones: other names, and they stay other names.
    ("ex\u0430mple.com", "xn--exmple-4nf.com"),
    ("\u0435xample.com", "xn--xample-2of.com"),
    ("exampl\u0435.com", "xn--exampl-8of.com"),
    ("example.c\u043em", "example.xn--cm-fmc"),
    ("\u00e9xample.com", "xn--xample-9ua.com"),
    ("e\u0301xample.com", "xn--xample-9ua.com"),
    ("\u0130stanbul.com", "xn--istanbul-o0e.com"),
    # Characters that stand in for a dot: not a label boundary, and not a name.
    ("example\u3002com", None),
    ("example\uff0ecom", None),
    ("example\uff61com", None),
    ("example.com\u2024", None),
    ("example\u2024com", None),
    # Whitespace, control characters and the punctuation of a URL: no name at all.
    ("exam ple.com", None),
    ("example.com ", None),
    (" example.com", None),
    ("example.com\n", None),
    ("example.com\r\n", None),
    ("example.com\x00", None),
    ("example.com\x00.evil.org", None),
    ("exam\tple.com", None),
    ("example.com:443", None),
    ("example.com/", None),
    ("example.com/@evil.org", None),
    ("http://example.com", None),
    ("evil.org@example.com", None),
    ("evil.org#example.com", None),
    ("evil.org?example.com", None),
    ("example.com\\evil.org", None),
    ("example,com", None),
    ("example_com", None),
    ("*.example.com", None),
    ("%65xample.com", None),
    # Labels and names beyond the bounds.
    ("e" * 64 + ".com", None),
    ("example." + "c" * 64, None),
    (".".join(["example"] * 32), None),
    # Compatibility spellings of the ASCII letters. The A-label conversion folds them onto the ASCII
    # name: they are that name, written in a way the host does not accept.
    ("\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com", "example.com"),
    ("ex\u00adample.com", "example.com"),
    ("exa\u200bmple.com", "example.com"),
    ("examp\u217ce.com", "example.com"),
]


@pytest.mark.proves("T3-RED-11")
@pytest.mark.parametrize(("spelling", "a_label_form"), CONFUSABLES, ids=[ascii(s)[1:41] for s, _ in CONFUSABLES])
def test_a_confusable_name_is_inside_exactly_when_it_is_the_name(spelling: str, a_label_form: str | None) -> None:
    assert normalize_name(spelling) == a_label_form
    requested = dest(name=spelling)
    assert (requested is None) == (a_label_form is None)
    assert admits(EXAMPLE, requested) == (a_label_form == "example.com")
    # A look-alike is not under the name either, and no spelling is inside an empty grant.
    assert not admits(grant(dest(suffix="*.example.com")), requested) or (a_label_form or "").endswith(".example.com")
    assert not admits((), requested)


@pytest.mark.proves("T3-RED-11")
def test_the_grant_may_be_spelled_in_any_equal_way_and_the_verdicts_stay_the_same() -> None:
    spellings = ["example.com", "EXAMPLE.COM", "example.com.", "Example.Com."]
    for granted_spelling in spellings:
        granted = grant(dest(name=granted_spelling))
        for spelling, a_label_form in CONFUSABLES:
            assert admits(granted, dest(name=spelling)) == (a_label_form == "example.com"), (granted_spelling, spelling)


# ------------------------------------------------------------------------------- the reference matcher
#: The non-ASCII labels the generators use, with their A-labels.
KNOWN_A_LABELS = {
    "b\u00fccher": "xn--bcher-kva",
    "B\u00dcCHER": "xn--bcher-kva",
    "\u043f\u0440\u0438\u043c\u0435\u0440": "xn--e1afmkfd",
    "\u4e2d\u6587": "xn--fiq228c",
}
# The generators change the case of whole names, so each label is known in both cases.
KNOWN_A_LABELS.update({label.upper(): a_label for label, a_label in list(KNOWN_A_LABELS.items())})
LETTERS_DIGITS_HYPHEN = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def ref_label(label: str) -> str | None:
    if label in KNOWN_A_LABELS:
        return KNOWN_A_LABELS[label]
    low = "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in label)
    if not 1 <= len(low) <= 63 or set(low) - LETTERS_DIGITS_HYPHEN or low[0] == "-" or low[-1] == "-":
        return None
    return low


def ref_name(text: str) -> list[str] | None:
    """The labels of a name, lower case, in A-label form; ``None`` when ``text`` is not a name."""
    if text.endswith("."):
        text = text[:-1]
    labels = []
    for label in text.split("."):
        converted = ref_label(label)
        if converted is None:
            return None
        labels.append(converted)
    if sum(len(label) for label in labels) + len(labels) - 1 > 253:
        return None
    return labels


def ref_network(text: str) -> tuple[int, int] | None:
    """The first and the last address of a network; ``None`` when ``text`` is not `a.b.c.d/len` with clear host bits."""
    parts = text.split("/")
    if len(parts) != 2:
        return None
    octets = parts[0].split(".")
    digits = set("0123456789")
    if len(octets) != 4 or any(
        not o or set(o) - digits or (len(o) > 1 and o[0] == "0") or int(o) > 255 for o in octets
    ):
        return None
    length = parts[1]
    if not length or set(length) - digits or (len(length) > 1 and length[0] == "0") or int(length) > 32:
        return None
    first = 0
    for octet in octets:
        first = first * 256 + int(octet)
    size = 2 ** (32 - int(length))
    if first % size:
        return None
    return first, first + size - 1


def ref_ports(ranges: tuple[tuple[int, int], ...]) -> frozenset[int] | None:
    """Every port of a port set, one by one; ``None`` when the set is empty or a range is not one."""
    if not ranges:
        return None
    ports: set[int] = set()
    for first, last in ranges:
        if not 1 <= first <= last <= 65535:
            return None
        ports.update(range(first, last + 1))
    return frozenset(ports)


@functools.cache
def ref_parse(raw: Raw) -> tuple[str, Any, frozenset[int]] | None:
    kind, text, ranges = raw
    ports = ref_ports(ranges)
    if ports is None:
        return None
    value: Any
    if kind == "name":
        value = ref_name(text)
    elif kind == "suffix":
        value = ref_name(text[2:]) if text.startswith("*.") else None
    else:
        value = ref_network(text)
    return None if value is None else (kind, value, ports)


def ref_inside(requested: Raw, granted: list[Raw]) -> bool:
    """AZ-8, read aloud. An entry that cannot be read is inside nothing; a grant is read entry by entry."""
    asked = ref_parse(requested)
    if asked is None:
        return False
    kind, value, ports = asked
    for entry in granted:
        parsed = ref_parse(entry)
        if parsed is None:
            continue
        g_kind, g_value, g_ports = parsed
        if not ports <= g_ports:
            continue
        if kind == "name" and g_kind == "name" and value == g_value:
            return True
        if kind in {"name", "suffix"} and g_kind == "suffix":
            under = len(value) > len(g_value) and value[len(value) - len(g_value) :] == g_value
            if under or (kind == "suffix" and value == g_value):
                return True
        if kind == "network" and g_kind == "network" and g_value[0] <= value[0] and value[1] <= g_value[1]:
            return True
    return False


def to_destination(raw: Raw) -> Destination | None:
    kind, text, ranges = raw
    return destination(
        name=text if kind == "name" else None,
        suffix=text if kind == "suffix" else None,
        network=text if kind == "network" else None,
        ports=list(ranges),
    )


LABELS = [
    "a", "b", "ab", "example", "evilexample", "com", "org", "A", "Example", "COM", "x-1", "1", "xn--bcher-kva",
    "b\u00fccher", "B\u00dcCHER", "\u043f\u0440\u0438\u043c\u0435\u0440", "\u4e2d\u6587",
    "", "-a", "a-", "a_b", "a b", "*", "a" * 63, "a" * 64,
]  # fmt: skip
BASES = [
    "10.0.0.0",
    "10.0.1.0",
    "10.1.0.0",
    "10.0.0.128",
    "10.0.0.1",
    "192.168.0.0",
    "172.16.0.0",
    "0.0.0.0",  # noqa: S104 - the base address of a network in a test of containment; nothing binds to it
    "255.255.255.255",
    "128.0.0.0",
]
ODD_NETWORKS = [
    "10.0.0.0",
    "10.0.0.0/33",
    "10.0.0.0/08",
    "256.0.0.0/8",
    "10.0.0.0/255.0.0.0",
    "::/0",
    "10.0.0/8",
    " 10.0.0.0/8",
    "10.0.0.0/8 ",
    "example.com",
    "",
]
PORTS = [1, 2, 21, 22, 23, 79, 80, 81, 442, 443, 444, 8080, 65534, 65535]


def _masked(base: str, length: int) -> str:
    number = 0
    for octet in base.split("."):
        number = number * 256 + int(octet)
    number -= number % 2 ** (32 - length)
    return ".".join(str(number // 256**i % 256) for i in (3, 2, 1, 0)) + f"/{length}"


names = st.builds(
    lambda labels, tail: ".".join(labels) + tail,
    st.lists(st.sampled_from(LABELS), min_size=1, max_size=4),
    st.sampled_from(["", "", "", ".", ".."]),
)
suffixes = st.builds(
    lambda head, name: head + name, st.sampled_from(["*.", "*.", "*.", "*.", "", "*", "**.", "*.*."]), names
)
networks = st.one_of(
    st.builds(_masked, st.sampled_from(BASES), st.integers(0, 32)),
    st.builds(lambda base, length: f"{base}/{length}", st.sampled_from(BASES), st.integers(0, 32)),
    st.sampled_from(ODD_NETWORKS),
)
port_bounds = st.sampled_from([0, *PORTS, 65536])
port_sets = st.lists(st.tuples(port_bounds, port_bounds), max_size=3).map(tuple) | st.lists(
    st.tuples(st.sampled_from(PORTS), st.sampled_from(PORTS)).map(lambda pair: (min(pair), max(pair))),
    min_size=1,
    max_size=3,
).map(tuple)
entries: st.SearchStrategy[Raw] = st.one_of(
    st.tuples(st.just("name"), names, port_sets),
    st.tuples(st.just("suffix"), suffixes, port_sets),
    st.tuples(st.just("network"), networks, port_sets),
)

# The same world without its malformed corners: entries a grant can hold.
good_names = st.builds(
    lambda labels, tail: ".".join(labels) + tail,
    st.lists(
        st.sampled_from([label for label in LABELS if ref_label(label) is not None and len(label) < 60]),
        min_size=1,
        max_size=4,
    ),
    st.sampled_from(["", "", "."]),
)
good_port_sets = st.lists(
    st.tuples(st.sampled_from(PORTS), st.sampled_from(PORTS)).map(lambda pair: (min(pair), max(pair))),
    min_size=1,
    max_size=3,
).map(tuple)
good_entries: st.SearchStrategy[Raw] = st.one_of(
    st.tuples(st.just("name"), good_names, good_port_sets),
    st.tuples(st.just("suffix"), good_names.map(lambda name: "*." + name), good_port_sets),
    st.tuples(st.just("network"), st.builds(_masked, st.sampled_from(BASES), st.integers(0, 32)), good_port_sets),
)


@pytest.mark.proves("T3-RED-11")
@given(entries)
def test_the_reference_and_the_implementation_agree_on_what_an_entry_is(raw: Raw) -> None:
    parsed, normalized = ref_parse(raw), to_destination(raw)
    assert (parsed is None) == (normalized is None), raw
    if parsed is not None and normalized is not None:
        kind, value, ports = parsed
        assert normalized.kind == kind
        assert normalized.value == (".".join(value) if kind != "network" else raw[1])
        assert {p for first, last in normalized.ports for p in range(first, last + 1)} == ports
        # Normalized ranges are sorted, disjoint and not adjacent: one port set has one form.
        assert all(a_last + 1 < b_first for (_, a_last), (b_first, _) in itertools.pairwise(normalized.ports))


@pytest.mark.proves("T3-RED-11")
@settings(max_examples=200)  # twice the cases of the profile: this is the property the file is for
@given(entries, st.lists(entries, max_size=5))
def test_the_implementation_gives_the_verdict_of_the_reference_matcher(requested: Raw, granted: list[Raw]) -> None:
    readable = tuple(entry for entry in map(to_destination, granted) if entry is not None)
    assert admits(readable, to_destination(requested)) == ref_inside(requested, granted), (requested, granted)


@st.composite
def related_pairs(draw: st.DrawFn) -> tuple[Raw, list[Raw]]:
    """A request made from an entry of the grant by a change that may or may not keep it inside."""
    granted = draw(st.lists(good_entries, min_size=1, max_size=4))
    kind, text, ranges = draw(st.sampled_from(granted))
    if kind == "network":
        base, length = text.split("/")
        change = draw(st.sampled_from(["same", "narrower", "wider", "sibling"]))
        if change == "narrower":
            text = _masked(base, draw(st.integers(int(length), 32)))
        elif change == "wider":
            text = _masked(base, draw(st.integers(0, int(length))))
        elif change == "sibling":
            text = _masked(draw(st.sampled_from(BASES)), int(length))
    else:
        name = text[2:] if kind == "suffix" else text
        change = draw(st.sampled_from(["same", "case", "dot", "under", "glued", "parent"]))
        if change == "case":
            name = name.upper() if draw(st.booleans()) else name.swapcase()
        elif change == "dot":
            name = name + "." if not name.endswith(".") else name[:-1]
        elif change == "under":
            name = draw(st.sampled_from(["a", "www", "A", "b\u00fccher"])) + "." + name
        elif change == "glued" and name.split(".")[0].isascii():
            name = draw(st.sampled_from(["evil", "x", "a"])) + name
        elif change == "parent" and "." in name:
            name = name.split(".", 1)[1]
        asked_kind = draw(st.sampled_from(["name", "name", kind]))
        kind, text = asked_kind, ("*." + name if asked_kind == "suffix" else name)
    port_change = draw(st.sampled_from(["same", "same", "one", "more"]))
    if port_change == "one":
        first, last = draw(st.sampled_from(ranges))
        port = draw(st.integers(first, last))
        ranges = ((port, port),)
    elif port_change == "more":
        ranges = (
            *ranges,
            draw(st.tuples(st.sampled_from(PORTS), st.sampled_from(PORTS)).map(lambda pair: (min(pair), max(pair)))),
        )
    return (kind, text, ranges), granted


@pytest.mark.proves("T3-RED-11")
@given(related_pairs())
def test_the_verdicts_agree_on_requests_that_are_close_to_the_grant(pair: tuple[Raw, list[Raw]]) -> None:
    requested, granted = pair
    readable = tuple(entry for entry in map(to_destination, granted) if entry is not None)
    assert len(readable) == len(granted)
    assert admits(readable, to_destination(requested)) == ref_inside(requested, granted), (requested, granted)


#: A small world of entries, well formed and not, in which every pair is judged by both.
WORLD_NAMES = [
    "example.com", "EXAMPLE.com.", "a.example.com", "a.b.example.com", "evilexample.com", "example.org", "com",
    "xn--bcher-kva.example", "b\u00fccher.example", "shop.B\u00dcCHER.example", "example..com", "",
]  # fmt: skip
WORLD_SUFFIXES = [
    "*.example.com",
    "*.a.example.com",
    "*.com",
    "*.b\u00fccher.example",
    "*.evilexample.com",
    "example.com",
    "*.",
]
WORLD_NETWORKS = [
    "0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "10.0.0.1/32", "192.168.0.0/16",
    "10.0.0.1/24", "10.0.0.0",
]  # fmt: skip
WORLD_PORTS: list[tuple[tuple[int, int], ...]] = [
    ((443, 443),),
    ((80, 80), (443, 443)),
    ((80, 90),),
    ((80, 84), (86, 90)),
    ((80, 85), (86, 90)),
    ((1, 65535),),
    (),
    ((0, 443),),
]


@pytest.mark.proves("T3-RED-11")
def test_every_pair_of_a_small_world_gets_the_verdict_of_the_reference_matcher() -> None:
    """Exhaustive where the properties above are random: every requested entry against every granted one."""
    world: list[Raw] = [
        (kind, text, ports)
        for kind, texts in (("name", WORLD_NAMES), ("suffix", WORLD_SUFFIXES), ("network", WORLD_NETWORKS))
        for text in texts
        for ports in WORLD_PORTS
    ]
    normalized = {raw: to_destination(raw) for raw in world}
    readable = [raw for raw in world if normalized[raw] is not None]
    assert {raw for raw in world if ref_parse(raw) is not None} == set(readable)
    verdicts: Counter[tuple[str, str, bool]] = Counter()
    for requested in world:
        for granted in readable:
            entry = normalized[granted]
            assert entry is not None
            expected = ref_inside(requested, [granted])
            assert admits((entry,), normalized[requested]) == expected, (requested, granted)
            verdicts[requested[0], granted[0], expected] += 1
    # Both verdicts were reached wherever the clause allows an entry to be inside, and only there.
    for requested_kind, granted_kind in itertools.product(("name", "suffix", "network"), repeat=2):
        possible = (requested_kind, granted_kind) in {
            ("name", "name"),
            ("name", "suffix"),
            ("suffix", "suffix"),
            ("network", "network"),
        }
        assert (verdicts[requested_kind, granted_kind, True] > 0) == possible, (requested_kind, granted_kind)
        assert verdicts[requested_kind, granted_kind, False] > 0
    assert sum(verdicts.values()) == len(world) * len(readable) > 20_000


# ------------------------------------------------------------------------------- what narrowing relies on
readable_entries = good_entries.map(to_destination)


@pytest.mark.proves("T3-RED-11")
@given(readable_entries)
def test_an_entry_is_inside_a_grant_that_holds_it(entry: Destination | None) -> None:
    assert entry is not None
    assert inside(entry, (entry,))


@pytest.mark.proves("T3-RED-11")
@given(readable_entries, st.lists(readable_entries, max_size=4), st.lists(readable_entries, max_size=4))
def test_adding_to_a_grant_never_takes_anything_out_of_it(
    entry: Destination | None, granted: list[Destination | None], more: list[Destination | None]
) -> None:
    assert entry is not None
    smaller = grant(*granted)
    larger = grant(*more, *granted, *more)
    if inside(entry, smaller):
        assert inside(entry, larger)


@pytest.mark.proves("T3-RED-11")
@given(related_pairs(), st.data())
def test_inside_carries_through_a_chain_of_grants(pair: tuple[Raw, list[Raw]], data: st.DataObject) -> None:
    """What is inside a narrowing is inside whatever the narrowing is inside: role, credential, agent credential."""
    requested_raw, middle_raw = pair
    requested = to_destination(requested_raw)
    middle = grant(*map(to_destination, middle_raw))
    outer = grant(*data.draw(st.lists(readable_entries, max_size=4)), *(middle if data.draw(st.booleans()) else ()))
    if requested is not None and inside(requested, middle) and all(inside(entry, outer) for entry in middle):
        assert inside(requested, outer)
