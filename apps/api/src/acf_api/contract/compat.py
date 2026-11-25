"""Is a new version of the contract artifacts compatible with a released one?

Within a major version of the public interface nothing is removed, renamed, retyped or made newly
required, and no request schema becomes stricter: a request that was valid when it was first sent is
still valid when it is repeated, and a client written for an earlier minor keeps working. This module
reads two versions of the generated artifacts and lists every difference that breaks that promise:

* the REST description (``api/openapi.yaml``): routes, parameters, request bodies, answers, their
  headers and who may call;
* the tool catalogue (``mcp/tools/*.json``): the tools, their inputs, their outputs and what their
  annotations promise;
* the problem registry (``api/problems/registry.yaml``): the codes, their problem types and their kinds.

What a caller sends and what a caller receives are held to opposite rules, so every schema is compared
in the direction it travels:

  a request    may be given more freedom: a new optional member, a wider range, one more accepted value.
               It breaks when something a caller could send is refused: a member removed, a member newly
               required, a tighter bound, a value no longer accepted, a changed pattern or default.
  an answer    may say more: a new member, a new value of an enumeration (a client treats a value it does
               not know as unknown). It breaks when something a caller could rely on is gone or is
               different: a member removed, a member that may now be absent or null, a changed type.

A schema that travels both ways is held to both rules.

The comparison is structural and conservative. Where it cannot prove that a change is compatible (a
pattern that changed, a union whose alternatives changed) it reports the change, and a person decides. A
decision that the change is compatible is recorded as the exact finding in a file of accepted findings,
which is reviewed like code. A finding in that file that no longer occurs fails the comparison, so the
file cannot outlive its reasons.

A new major version may break. A comparison across majors lists what it found and passes.
"""

from __future__ import annotations

import argparse
import enum
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeGuard

import yaml

OPENAPI: Final = "api/openapi.yaml"
PROBLEMS: Final = "api/problems/registry.yaml"
TOOLS: Final = "mcp/tools/"

_NULL: Final = "null"
_METHODS: Final = ("get", "put", "post", "delete", "patch", "head", "options", "trace", "query")
#: A request may lower these and may not raise them.
_LOWER_BOUNDS: Final = ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties")
#: A request may raise these and may not lower them.
_UPPER_BOUNDS: Final = ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties")
_REF_DEPTH: Final = 32
_ABSENT: Final = object()


class NotComparable(Exception):
    """One of the two versions cannot be read as contract artifacts. The message says what is wrong."""


class Direction(enum.Enum):
    """Which way a schema travels, and so which rule it is held to."""

    REQUEST = "request"
    ANSWER = "answer"


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _show(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _types(node: Mapping[str, Any]) -> frozenset[str] | None:
    """The JSON types a schema names, or None where it names none."""
    declared = node.get("type")
    if isinstance(declared, str):
        return frozenset({declared})
    if isinstance(declared, list):
        return frozenset(t for t in declared if isinstance(t, str))
    return None


def _values_of(types: frozenset[str]) -> frozenset[str]:
    """The kinds of value a set of types admits: every integer is a number."""
    return types | {"integer"} if "number" in types else types


def _named(types: frozenset[str] | None) -> str:
    return "any type" if types is None else " or ".join(sorted(types)) or "nothing"


def _alternatives(node: Mapping[str, Any]) -> tuple[bool, list[Mapping[str, Any]]]:
    """Whether a schema admits null, and its alternatives that are not null."""
    branches = node.get("anyOf", node.get("oneOf"))
    if isinstance(branches, list):
        rest = [b for b in branches if isinstance(b, Mapping) and _types(b) != frozenset({_NULL})]
        return len(rest) != len(branches), rest
    types = _types(node)
    if types is not None and _NULL in types:
        others = sorted(types - {_NULL})
        if not others:
            return True, []
        return True, [{**node, "type": others[0] if len(others) == 1 else others}]
    return False, [node]


def _is_number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, int | float) and not isinstance(value, bool)


class _Comparison:
    """One pass over two versions of one document. Findings keep the order in which they were met."""

    def __init__(
        self, old: Mapping[str, Any], new: Mapping[str, Any], *, subject: str, request: str, answer: str
    ) -> None:
        self.old, self.new = old, new
        self._subject = subject
        self._labels = {Direction.REQUEST: request, Direction.ANSWER: answer}
        #: Named schemas already compared, by direction: a schema is reported once, and a cycle ends.
        self._seen: set[tuple[str, str, Direction]] = set()
        self.findings: list[str] = []

    def report(self, where: str, what: str) -> None:
        finding = f"{self._subject}: {where}: {what}"
        if finding not in self.findings:
            self.findings.append(finding)

    # ------------------------------------------------------------------------------------ references
    def resolve(self, document: Mapping[str, Any], node: object) -> tuple[Mapping[str, Any], str | None]:
        """A node with its references followed, and the name of the first thing it referred to."""
        name: str | None = None
        for _ in range(_REF_DEPTH):
            if not isinstance(node, Mapping):
                return {}, name
            reference = node.get("$ref")
            if not isinstance(reference, str):
                return node, name
            if not reference.startswith("#/"):
                raise NotComparable(f"{self._subject}: the reference `{reference}` leaves the document")
            target: object = document
            for part in reference[2:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                target = target.get(key, _ABSENT) if isinstance(target, Mapping) else _ABSENT
                if target is _ABSENT:
                    raise NotComparable(f"{self._subject}: the reference `{reference}` points at nothing")
            name = name or reference.rsplit("/", 1)[-1]
            node = target
        raise NotComparable(f"{self._subject}: the references from `{name}` never end")

    # --------------------------------------------------------------------------------------- schemas
    def schema(self, old: object, new: object, direction: Direction, where: str) -> None:
        """Compare one schema of the old version with its counterpart, by the rule of its direction."""
        old_node, old_name = self.resolve(self.old, old)
        new_node, new_name = self.resolve(self.new, new)
        if old_name is not None:
            seen = (old_name, new_name or "", direction)
            if seen in self._seen:
                return
            self._seen.add(seen)
            where = f"{self._labels[direction]} {old_name}"
        if (
            direction is Direction.REQUEST
            and "default" in old_node
            and old_node["default"] != new_node.get("default", _ABSENT)
        ):
            now = _show(new_node["default"]) if "default" in new_node else "none"
            self.report(where, f"the default changed from {_show(old_node['default'])} to {now}")
        old_null, old_alternatives = _alternatives(old_node)
        new_null, new_alternatives = _alternatives(new_node)
        if direction is Direction.REQUEST and old_null and not new_null:
            self.report(where, "null is no longer accepted")
        if direction is Direction.ANSWER and new_null and not old_null:
            self.report(where, "may now be null")
        if len(old_alternatives) == 1 and len(new_alternatives) == 1:
            one_old, one_new = old_alternatives[0], new_alternatives[0]
            if one_old is old_node and one_new is new_node:
                self._keywords(old_node, new_node, direction, where)
            else:
                self.schema(one_old, one_new, direction, where)
            return
        self._union(old_alternatives, new_alternatives, direction, where)

    @staticmethod
    def _alternative_name(node: Mapping[str, Any], position: int) -> str:
        reference = node.get("$ref")
        if isinstance(reference, str):
            return reference.rsplit("/", 1)[-1]
        if "const" in node:
            return f"the constant {_show(node['const'])}"
        types = _types(node)
        return _named(types) if types is not None else f"alternative {position + 1}"

    def _union(
        self, old: list[Mapping[str, Any]], new: list[Mapping[str, Any]], direction: Direction, where: str
    ) -> None:
        """A choice between alternatives: a request may gain one and an answer may lose one, never the reverse."""
        before = {self._alternative_name(node, i): node for i, node in enumerate(old)}
        after = {self._alternative_name(node, i): node for i, node in enumerate(new)}
        if direction is Direction.REQUEST:
            for name in before.keys() - after.keys():
                self.report(where, f"{name} is no longer accepted")
        else:
            for name in after.keys() - before.keys():
                self.report(where, f"may now be {name}")
        for name, node in before.items():
            if name in after:
                self.schema(node, after[name], direction, where)

    def _keywords(self, old: Mapping[str, Any], new: Mapping[str, Any], direction: Direction, where: str) -> None:
        self._type(old, new, direction, where)
        self._values(old, new, direction, where)
        if direction is Direction.REQUEST:
            self._bounds(old, new, where)
        self._members(old, new, direction, where)
        old_items, new_items = old.get("items"), new.get("items")
        if isinstance(old_items, Mapping):
            if isinstance(new_items, Mapping):
                self.schema(old_items, new_items, direction, f"{where}[]")
            elif direction is Direction.ANSWER:
                self.report(where, "its items are no longer described")

    def _type(self, old: Mapping[str, Any], new: Mapping[str, Any], direction: Direction, where: str) -> None:
        before, after = _types(old), _types(new)
        if before == after:
            return
        # What may travel must stay inside what the other side was told to expect.
        narrow, wide = (before, after) if direction is Direction.REQUEST else (after, before)
        if wide is None:
            return
        if narrow is None or not _values_of(narrow) <= _values_of(wide):
            self.report(where, f"the type changed from {_named(before)} to {_named(after)}")

    def _values(self, old: Mapping[str, Any], new: Mapping[str, Any], direction: Direction, where: str) -> None:
        if "const" in old and "const" in new:
            if old["const"] != new["const"]:
                self.report(where, f"the constant changed from {_show(old['const'])} to {_show(new['const'])}")
        elif "const" in new and direction is Direction.REQUEST:
            self.report(where, f"only {_show(new['const'])} is accepted now")
        elif "const" in old and direction is Direction.ANSWER:
            self.report(where, f"is no longer always {_show(old['const'])}")
        if direction is Direction.REQUEST and isinstance(new.get("enum"), list):
            accepted = {_show(v) for v in new["enum"]}
            if isinstance(old.get("enum"), list):
                lost = sorted({_show(v) for v in old["enum"]} - accepted)
            elif "const" in old:
                lost = sorted({_show(old["const"])} - accepted)
            else:
                self.report(where, f"only {', '.join(sorted(accepted))} are accepted now")
                lost = []
            if lost:
                self.report(where, f"{', '.join(lost)} {'is' if len(lost) == 1 else 'are'} no longer accepted")
        if "format" in old and "format" in new and old["format"] != new["format"]:
            self.report(where, f"the format changed from `{old['format']}` to `{new['format']}`")

    def _bounds(self, old: Mapping[str, Any], new: Mapping[str, Any], where: str) -> None:
        """A request schema never becomes stricter."""
        for names, raised in ((_LOWER_BOUNDS, True), (_UPPER_BOUNDS, False)):
            for name in names:
                before, after = old.get(name), new.get(name)
                if not _is_number(after):
                    continue
                if not _is_number(before):
                    self.report(where, f"`{name}` {_show(after)} was added")
                elif (after > before) if raised else (after < before):
                    moved = "raised" if raised else "lowered"
                    self.report(where, f"`{name}` was {moved} from {_show(before)} to {_show(after)}")
        if "pattern" in new and new["pattern"] != old.get("pattern"):
            self.report(where, "the pattern changed" if "pattern" in old else "a pattern was added")
        if "multipleOf" in new and new["multipleOf"] != old.get("multipleOf"):
            self.report(where, "`multipleOf` changed" if "multipleOf" in old else "`multipleOf` was added")
        if new.get("uniqueItems") is True and old.get("uniqueItems") is not True:
            self.report(where, "its items must now be unique")

    def _members(self, old: Mapping[str, Any], new: Mapping[str, Any], direction: Direction, where: str) -> None:
        old_members, new_members = _mapping(old.get("properties")), _mapping(new.get("properties"))
        old_required = {r for r in old.get("required") or () if isinstance(r, str)}
        new_required = {r for r in new.get("required") or () if isinstance(r, str)}
        for name in old_members:
            if name not in new_members:
                self.report(where, f"member `{name}` was removed")
        if direction is Direction.REQUEST:
            for name in sorted(new_required - old_required):
                self.report(where, f"member `{name}` is newly required")
        else:
            for name in sorted(old_required - new_required):
                if name in new_members:
                    self.report(where, f"member `{name}` may now be absent")
        for name, member in old_members.items():
            if name in new_members:
                self.schema(member, new_members[name], direction, f"{where}.{name}")
        self._other_members(
            old, new, direction, where, described=bool(old_members) or _types(old) == frozenset({"object"})
        )

    def _other_members(
        self, old: Mapping[str, Any], new: Mapping[str, Any], direction: Direction, where: str, *, described: bool
    ) -> None:
        """Members a schema admits without naming them: by a pattern of their names, or all the rest."""
        old_patterns, new_patterns = _mapping(old.get("patternProperties")), _mapping(new.get("patternProperties"))
        for pattern, member in old_patterns.items():
            if pattern in new_patterns:
                self.schema(member, new_patterns[pattern], direction, f"{where}.*")
            elif direction is Direction.REQUEST:
                self.report(where, f"members named like `{pattern}` are no longer accepted")
        old_rest, new_rest = old.get("additionalProperties", True), new.get("additionalProperties", True)
        if isinstance(old_rest, Mapping) and isinstance(new_rest, Mapping):
            self.schema(old_rest, new_rest, direction, f"{where}.*")
        elif direction is Direction.REQUEST and described and old_rest is not False and new_rest is not True:
            # They were accepted, freely or by a schema of their own, and are now refused or restricted.
            self.report(where, "members the schema does not name are no longer accepted as they were")


# ------------------------------------------------------------------------------------------ REST
def _parameters(
    walk: _Comparison, document: Mapping[str, Any], item: Mapping[str, Any], operation: Mapping[str, Any]
) -> dict[tuple[str, str], Mapping[str, Any]]:
    """The parameters of one operation by place and name. The operation's own replace the path's."""
    found: dict[tuple[str, str], Mapping[str, Any]] = {}
    for listed in (item.get("parameters"), operation.get("parameters")):
        for entry in listed if isinstance(listed, list) else ():
            parameter, _ = walk.resolve(document, entry)
            place, name = str(parameter.get("in", "")), str(parameter.get("name", ""))
            # Header names are compared without regard to case, as HTTP compares them.
            found[(place, name.lower() if place == "header" else name)] = parameter
    return found


def _requirements(document: Mapping[str, Any], operation: Mapping[str, Any]) -> set[frozenset[str]]:
    """The alternatives by which a caller may be allowed. The empty one: without a credential."""
    stated = operation.get("security", document.get("security"))
    if not isinstance(stated, list) or not stated:
        return {frozenset()}
    return {frozenset(_mapping(entry)) for entry in stated}


def _operation(
    walk: _Comparison, route: str, old_item: Mapping[str, Any], new_item: Mapping[str, Any], method: str
) -> None:
    old, new = _mapping(old_item.get(method)), _mapping(new_item.get(method))
    before, after = _parameters(walk, walk.old, old_item, old), _parameters(walk, walk.new, new_item, new)
    for key, parameter in before.items():
        place, name = key[0], parameter.get("name")
        counterpart = after.get(key)
        if counterpart is None:
            walk.report(route, f"the {place} parameter `{name}` was removed")
            continue
        if counterpart.get("required") is True and parameter.get("required") is not True:
            walk.report(route, f"the {place} parameter `{name}` is newly required")
        walk.schema(
            parameter.get("schema", {}),
            counterpart.get("schema", {}),
            Direction.REQUEST,
            f"{route}: {place} parameter `{name}`",
        )
    for key, parameter in after.items():
        if key not in before and parameter.get("required") is True:
            walk.report(route, f"the new {key[0]} parameter `{parameter.get('name')}` is required")

    old_body, _ = walk.resolve(walk.old, old.get("requestBody"))
    new_body, _ = walk.resolve(walk.new, new.get("requestBody"))
    if new_body.get("required") is True and old_body.get("required") is not True:
        walk.report(route, "a request body is newly required")
    for media, content in _mapping(old_body.get("content")).items():
        counterpart = _mapping(new_body.get("content")).get(media)
        if counterpart is None:
            walk.report(route, f"a request body of `{media}` is no longer accepted")
            continue
        walk.schema(
            _mapping(content).get("schema", {}),
            _mapping(counterpart).get("schema", {}),
            Direction.REQUEST,
            f"{route}: request body",
        )

    answers = {str(status): answer for status, answer in _mapping(new.get("responses")).items()}
    for status, answer in _mapping(old.get("responses")).items():
        _answer(walk, route, str(status), answer, answers.get(str(status), _ABSENT))

    for requirement in _requirements(walk.old, old) - _requirements(walk.new, new):
        how = "without a credential" if not requirement else f"with `{'` and `'.join(sorted(requirement))}`"
        walk.report(route, f"can no longer be called {how}")


def _answer(walk: _Comparison, route: str, status: str, old: object, new: object) -> None:
    if new is _ABSENT:
        # An error status that is no longer listed takes nothing from a client: it decides by the code.
        if status.startswith("2"):
            walk.report(route, f"the answer `{status}` was removed")
        return
    before, name = walk.resolve(walk.old, old)
    after, _ = walk.resolve(walk.new, new)
    where = f"{route}: answer {status}" if name is None else f"answer {name}"
    headers = {str(header).lower() for header in _mapping(after.get("headers"))}
    for header in _mapping(before.get("headers")):
        if str(header).lower() not in headers:
            walk.report(where, f"the header `{header}` was removed")
    for media, content in _mapping(before.get("content")).items():
        counterpart = _mapping(after.get("content")).get(media)
        if counterpart is None:
            walk.report(where, f"is no longer given as `{media}`")
            continue
        walk.schema(
            _mapping(content).get("schema", {}), _mapping(counterpart).get("schema", {}), Direction.ANSWER, where
        )


def breaking_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """What the REST description ``new`` takes from a caller who was written for ``old``."""
    walk = _Comparison(old, new, subject="REST", request="request schema", answer="answer schema")
    new_paths = _mapping(new.get("paths"))
    for path, item in _mapping(old.get("paths")).items():
        counterpart = _mapping(new_paths.get(path))
        for method in _METHODS:
            if method not in _mapping(item):
                continue
            route = f"{method.upper()} {path}"
            if method not in counterpart:
                walk.report(route, "the route was removed")
            else:
                _operation(walk, route, _mapping(item), counterpart, method)
    return walk.findings


# ------------------------------------------------------------------------------------------ tools
#: What an annotation promised, and what a host may have decided on it.
_PROMISES: Final = (
    ("readOnlyHint", True, "no longer promises to change nothing"),
    ("idempotentHint", True, "no longer promises that a repeated call changes nothing more"),
    ("destructiveHint", False, "no longer promises to destroy nothing"),
    ("openWorldHint", False, "no longer promises to stay inside the platform"),
)


def breaking_tool_changes(old: Mapping[str, Mapping[str, Any]], new: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """What the tool catalogue ``new`` takes from an agent host that was written for ``old``. By tool name."""
    findings: list[str] = []
    for name, tool in old.items():
        counterpart = new.get(name)
        if counterpart is None:
            findings.append(f"tool {name}: the tool was removed")
            continue
        for part, direction, where in (
            ("inputSchema", Direction.REQUEST, "input"),
            ("outputSchema", Direction.ANSWER, "output"),
        ):
            before, after = tool.get(part), counterpart.get(part)
            if not isinstance(before, Mapping):
                continue
            if not isinstance(after, Mapping):
                findings.append(f"tool {name}: its {where} is no longer described")
                continue
            walk = _Comparison(before, after, subject=f"tool {name}", request="input schema", answer="output schema")
            walk.schema(before, after, direction, where)
            findings.extend(walk.findings)
        promised, promises = _mapping(tool.get("annotations")), _mapping(counterpart.get("annotations"))
        findings.extend(
            f"tool {name}: {broken}"
            for hint, value, broken in _PROMISES
            if promised.get(hint) is value and promises.get(hint) is not value
        )
    return findings


# -------------------------------------------------------------------------------------- problems
def breaking_problem_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """Codes are never removed or renamed, and a code keeps its problem type and its kind."""
    findings: list[str] = []
    after = {entry.get("code"): entry for entry in new.get("codes") or () if isinstance(entry, Mapping)}
    for entry in old.get("codes") or ():
        if not isinstance(entry, Mapping):
            continue
        code = entry.get("code")
        counterpart = after.get(code)
        if counterpart is None:
            findings.append(f"problems: the code `{code}` was removed")
            continue
        findings.extend(
            f"problems: the {what} of `{code}` changed from `{entry.get(member)}` to `{counterpart.get(member)}`"
            for member, what in (("type", "problem type"), ("kind", "kind"))
            if entry.get(member) != counterpart.get(member)
        )
    return findings


# ------------------------------------------------------------------------------------- versions
@dataclass(frozen=True, slots=True)
class Report:
    """The result of comparing a candidate with a baseline."""

    baseline_version: str
    candidate_version: str
    findings: tuple[str, ...]

    @property
    def new_major(self) -> bool:
        """Whether the candidate is a new major version, which may break."""
        return _major(self.baseline_version) != _major(self.candidate_version)


def _major(version: str) -> str:
    return version.split(".", 1)[0]


def _document(files: Mapping[str, str], path: str, which: str) -> Mapping[str, Any]:
    try:
        loaded = json.loads(files[path]) if path.endswith(".json") else yaml.safe_load(files[path])
    except (ValueError, yaml.YAMLError) as e:
        raise NotComparable(f"{path} of the {which} cannot be parsed: {e}") from e
    if not isinstance(loaded, Mapping):
        raise NotComparable(f"{path} of the {which} is not a mapping")
    return loaded


def _version(description: Mapping[str, Any], which: str) -> str:
    version = _mapping(description.get("info")).get("version")
    if not isinstance(version, str) or not version:
        raise NotComparable(f"{OPENAPI} of the {which} states no `info.version`")
    return version


def _tools(files: Mapping[str, str], which: str) -> dict[str, Mapping[str, Any]]:
    """The tool definitions of one version, by tool name."""
    return {
        path.removeprefix(TOOLS).removesuffix(".json"): _document(files, path, which)
        for path in sorted(files)
        if path.startswith(TOOLS) and path.endswith(".json")
    }


def compare(baseline: Mapping[str, str], candidate: Mapping[str, str]) -> Report:
    """Compare two sets of artifacts, each given as its text by path under the ``protocols`` directory."""
    for which, files in (("baseline", baseline), ("candidate", candidate)):
        if OPENAPI not in files:
            raise NotComparable(f"the {which} has no {OPENAPI}")
    old, new = _document(baseline, OPENAPI, "baseline"), _document(candidate, OPENAPI, "candidate")
    findings = breaking_changes(old, new)
    findings += breaking_tool_changes(_tools(baseline, "baseline"), _tools(candidate, "candidate"))
    if PROBLEMS in baseline:
        if PROBLEMS not in candidate:
            findings.append(f"problems: {PROBLEMS} was removed")
        else:
            findings += breaking_problem_changes(
                _document(baseline, PROBLEMS, "baseline"), _document(candidate, PROBLEMS, "candidate")
            )
    return Report(_version(old, "baseline"), _version(new, "candidate"), tuple(findings))


def read_tree(root: Path) -> dict[str, str]:
    """The artifacts a comparison reads, from a ``protocols`` directory."""
    files: dict[str, str] = {}
    try:
        for relative in (OPENAPI, PROBLEMS):
            if (root / relative).is_file():
                files[relative] = (root / relative).read_text(encoding="utf-8")
        for tool in sorted((root / TOOLS).glob("*.json")):
            files[f"{TOOLS}{tool.name}"] = tool.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise NotComparable(f"{root} cannot be read: {e}") from e
    return files


def read_accepted(path: Path) -> list[str]:
    """The reviewed findings of a file: one exact finding a line. Empty lines and ``#`` lines are not findings."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise NotComparable(f"{path} cannot be read: {e}") from e
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def run(baseline: Path, candidate: Path | None = None, accepted: Path | None = None) -> int:
    """Compare, say what was found, and return the exit status: 0 compatible, 1 breaking, 2 not comparable."""
    try:
        if candidate is None:
            from acf_api.contract import generate  # noqa: PLC0415 - only this case needs the implementation

            new = generate.build_all()
        else:
            new = read_tree(candidate)
        report = compare(read_tree(baseline), new)
        reviewed = read_accepted(accepted) if accepted is not None else []
    except NotComparable as e:
        sys.stderr.write(f"acf-api: {e}\n")
        return 2
    return _say(report, reviewed)


def _lines(findings: Iterable[str]) -> str:
    return "".join(f"  {finding}\n" for finding in findings)


def _counted(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _say(report: Report, reviewed: list[str]) -> int:
    versions = f"{report.candidate_version} against {report.baseline_version}"
    open_findings = [finding for finding in report.findings if finding not in reviewed]
    stale = [finding for finding in reviewed if finding not in report.findings]
    if report.new_major:
        found = _counted(len(report.findings), "breaking change")
        sys.stdout.write(f"{versions}: a new major version, which may break. {found}:\n")
        sys.stdout.write(_lines(report.findings))
        return 0
    if open_findings:
        found = _counted(len(open_findings), "change")
        sys.stderr.write(f"{versions}: {found} would break a caller of {report.baseline_version}:\n")
        sys.stderr.write(_lines(open_findings))
        sys.stderr.write(
            "within a major version nothing is removed, retyped or made newly required, and no request becomes stricter\n"
        )
    if stale:
        sys.stderr.write(
            f"{versions}: {_counted(len(stale), 'accepted finding')} did not occur; remove what is stale:\n"
        )
        sys.stderr.write(_lines(stale))
    if open_findings or stale:
        return 1
    accepted = f" ({_counted(len(reviewed), 'reviewed exception')})" if reviewed else ""
    sys.stdout.write(f"{versions}: compatible{accepted}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acf-api compat", description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--baseline", type=Path, required=True, help="the `protocols` directory of a released version")
    parser.add_argument("--candidate", type=Path, help="a `protocols` directory; by default, what this code generates")
    parser.add_argument("--accept", type=Path, help="a file of reviewed findings, one exact finding a line")
    args = parser.parse_args(argv)
    return run(args.baseline, args.candidate, args.accept)


if __name__ == "__main__":
    raise SystemExit(main())
