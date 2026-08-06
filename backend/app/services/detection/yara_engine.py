"""Pure-Python YARA-subset rule engine (Phase 9).

The native ``yara`` package is a compiled C extension that is not portable to
every deployment target (e.g. a Python 3.14 venv with no wheels). This module
implements a dependency-free parser + evaluator for a practical YARA grammar
subset so rules can be scanned without native libs:

* ``rule name : tag1 tag2 { meta: ... strings: ... condition: ... }``
* text strings with ``ascii`` / ``wide`` / ``nocase`` / ``fullword`` modifiers
* hex strings with byte literals, ``??`` wildcards, and ``[n]`` / ``[n-m]`` jumps
* condition expressions: ``and`` / ``or`` / ``not``, comparisons, ``true`` /
  ``false``, ``$a`` / ``#a`` / ``@a``, ``$a at N``, ``$a in (lo..hi)``, and
  ``of`` operators (``all`` / ``any`` / ``N of them|(ids)``)
* ``//`` and ``/* */`` comments; ``meta`` and ``tags`` are parsed and exposed

Unsupported YARA features (regular-expression strings, modules such as ``pe``,
``include`` / ``import``) are rejected with a clear error instead of misparsed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_KEYWORDS = {
    "rule",
    "meta",
    "strings",
    "condition",
    "and",
    "or",
    "not",
    "all",
    "any",
    "of",
    "them",
    "in",
    "at",
    "ascii",
    "wide",
    "nocase",
    "fullword",
    "true",
    "false",
    "private",
    "global",
    "import",
    "include",
}

_HEX_WILDCARD = "??"

_TEXT_MODIFIERS = frozenset({"ascii", "wide", "nocase", "fullword"})


class YaraRuleError(ValueError):
    """Raised when a rule cannot be parsed or evaluated."""


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------


def _tokenize(source: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    index = 0
    length = len(source)
    in_strings = False

    while index < length:
        ch = source[index]

        if ch.isspace():
            index += 1
            continue

        if source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue

        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end == -1:
                raise YaraRuleError("unterminated block comment")
            index = end + 2
            continue

        if ch == '"':
            buffer: list[str] = []
            index += 1
            while index < length:
                char = source[index]
                if char == "\\":
                    if index + 1 >= length:
                        raise YaraRuleError("unterminated escape in string literal")
                    buffer.append(_unescape(source[index + 1]))
                    index += 2
                    continue
                if char == '"':
                    break
                buffer.append(char)
                index += 1
            else:
                raise YaraRuleError("unterminated string literal")
            tokens.append(("text", "".join(buffer)))
            index += 1
            continue

        if ch in ("#", "@", "$"):
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(("ref", (ch, source[index + 1 : end])))
            index = end
            continue

        if ch.isdigit():
            end = index
            while end < length and source[end].isdigit():
                end += 1
            tokens.append(("int", int(source[index:end])))
            index = end
            continue

        if ch.isalpha() or ch == "_":
            end = index
            while end < length and (source[end].isalnum() or source[end] == "_"):
                end += 1
            word = source[index:end]
            if word == "strings":
                probe = end
                while probe < length and source[probe].isspace():
                    probe += 1
                if probe < length and source[probe] == ":":
                    in_strings = True
            elif word == "condition":
                in_strings = False
            tokens.append(("kw" if word in _KEYWORDS else "id", word))
            index = end
            continue

        if ch == "{" and in_strings:
            close = source.find("}", index + 1)
            if close == -1:
                raise YaraRuleError("unterminated hex string")
            tokens.append(("hex", source[index + 1 : close]))
            index = close + 1
            continue

        two = source[index : index + 2]
        if two in ("==", "!=", "<=", ">=", ".."):
            tokens.append(("punct", two))
            index += 2
            continue

        if ch in "(){}[],:;=<>":
            tokens.append(("punct", ch))
            index += 1
            continue

        raise YaraRuleError(f"unexpected character {ch!r} at offset {index}")

    return tokens


def _unescape(char: str) -> str:
    return {
        "n": "\n",
        "t": "\t",
        "r": "\r",
        '"': '"',
        "\\": "\\",
    }.get(char, char)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[tuple[str, Any]]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self, kind: str | None = None, value: Any = None) -> tuple[str, Any] | None:
        if self._pos >= len(self._tokens):
            return None
        kind_at, value_at = self._tokens[self._pos]
        if kind is not None and kind_at != kind:
            return None
        if value is not None and value_at != value:
            return None
        return (kind_at, value_at)

    def _take(self, kind: str | None = None, value: Any = None) -> tuple[str, Any]:
        token = self._peek(kind, value)
        if token is None:
            raise YaraRuleError(f"expected {kind!r} token but found end of rule")
        self._pos += 1
        return token

    def _take_kind(self, kind: str) -> Any:
        return self._take(kind)[1]

    def parse_rules(self) -> list[YaraRule]:
        rules: list[YaraRule] = []
        while self._peek() is not None:
            if self._peek("kw", "rule") is None:
                ahead = self._peek()
                if ahead is not None and ahead[0] == "kw" and ahead[1] in ("import", "include"):
                    raise YaraRuleError(f"'{ahead[1]}' is not supported by the subset engine")
                raise YaraRuleError("expected 'rule' keyword")
            rules.append(self._parse_rule())
        return rules

    def _parse_rule(self) -> YaraRule:
        self._take("kw", "rule")
        if self._peek("kw", "private") is not None or self._peek("kw", "global") is not None:
            self._take()
        name = self._take_kind("id")
        tags: list[str] = []
        if self._peek("punct", ":") is not None:
            self._take()
            while self._peek("id") is not None:
                tags.append(self._take_kind("id"))
        self._take("punct", "{")

        meta: dict[str, Any] = {}
        strings: dict[str, tuple[str, Any, frozenset[str]]] = {}
        condition: Any = ("false",)

        while True:
            if self._peek("kw", "meta") is not None:
                self._take()
                self._take("punct", ":")
                meta.update(self._parse_meta())
                continue
            if self._peek("kw", "strings") is not None:
                self._take()
                self._take("punct", ":")
                strings.update(self._parse_strings())
                continue
            if self._peek("kw", "condition") is not None:
                self._take()
                self._take("punct", ":")
                condition = self._parse_expr()
                continue
            break

        self._take("punct", "}")
        return YaraRule(name=name, tags=tags, meta=meta, strings=strings, condition=condition)

    def _parse_meta(self) -> dict[str, Any]:
        entries: dict[str, Any] = {}
        while self._peek("id") is not None:
            key = self._take_kind("id")
            self._take("punct", "=")
            kind, value = self._take()
            if kind == "text":
                entries[key] = value
            elif kind == "int":
                entries[key] = int(value)
            elif kind == "kw" and value in ("true", "false"):
                entries[key] = value == "true"
            else:
                raise YaraRuleError(f"unsupported meta value for {key}")
        return entries

    def _parse_strings(self) -> dict[str, tuple[str, Any, frozenset[str]]]:
        definitions: dict[str, tuple[str, Any, frozenset[str]]] = {}
        while self._peek("ref") is not None:
            marker, name = self._take("ref")[1]
            if marker != "$":
                raise YaraRuleError("string definitions must use '$' references")
            string_id = f"${name}"
            self._take("punct", "=")
            kind, value = self._take()
            if kind not in ("text", "hex"):
                raise YaraRuleError(f"unsupported string definition for {string_id}")
            modifiers: set[str] = set()
            if kind == "text":
                while (modifier := self._peek("kw")) is not None and modifier[1] in _TEXT_MODIFIERS:
                    modifiers.add(self._take_kind("kw"))
            definitions[string_id] = (kind, value, frozenset(modifiers))
        return definitions

    def _parse_expr(self) -> Any:
        return self._parse_or()

    def _parse_or(self) -> Any:
        left = self._parse_and()
        while self._peek("kw", "or") is not None:
            self._take()
            left = ("or", left, self._parse_and())
        return left

    def _parse_and(self) -> Any:
        left = self._parse_not()
        while self._peek("kw", "and") is not None:
            self._take()
            left = ("and", left, self._parse_not())
        return left

    def _parse_not(self) -> Any:
        if self._peek("kw", "not") is not None:
            self._take()
            return ("not", self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self) -> Any:
        left = self._parse_primary()
        op_token = self._peek()
        if op_token is None:
            return left
        kind, value = op_token
        if kind == "punct" and value in ("==", "!=", "<", ">", "<=", ">="):
            self._take()
            right = self._parse_primary()
            return ("cmp", value, left, right)
        if kind == "kw" and value == "at":
            self._take()
            offset = self._parse_primary()
            return ("at", left, offset)
        if kind == "kw" and value == "in":
            self._take()
            self._take("punct", "(")
            low = self._parse_expr()
            self._take("punct", "..")
            high = self._parse_expr()
            self._take("punct", ")")
            return ("in", left, low, high)
        return left

    def _parse_primary(self) -> Any:
        token = self._peek()
        if token is None:
            raise YaraRuleError("expected expression but found end of rule")
        kind, value = token

        if kind == "int":
            self._take()
            if self._peek("kw", "of") is not None:
                self._take()
                return self._parse_of(int(value))
            return ("int", int(value))
        if kind == "kw" and value in ("true", "false"):
            self._take()
            return ("bool", value == "true")
        if kind == "ref":
            self._take()
            marker, name = value
            string_id = f"${name}"
            if marker == "$":
                return ("str", string_id)
            if marker == "#":
                return ("count", string_id)
            return ("first", string_id)
        if kind == "text":
            raise YaraRuleError(
                "string literals are not supported in conditions; use a string "
                "identifier such as $a"
            )
        if kind == "punct" and value == "(":
            self._take()
            inner = self._parse_expr()
            self._take("punct", ")")
            return inner

        if kind == "kw" and value in ("all", "any"):
            self._take()
            self._take("kw", "of")
            return self._parse_of("all" if value == "all" else "any")

        raise YaraRuleError(f"unexpected token in condition: {kind}:{value!r}")

    def _parse_of(self, quantifier: str | int) -> Any:
        if self._peek("kw", "them") is not None:
            self._take()
            return ("of", quantifier, None)
        self._take("punct", "(")
        ids: list[str] = []
        while self._peek("ref") is not None:
            marker, name = self._take("ref")[1]
            if marker != "$":
                raise YaraRuleError("'of' sets may only contain '$' references")
            ids.append(f"${name}")
            if self._peek("punct", ",") is not None:
                self._take()
        self._take("punct", ")")
        if not ids:
            raise YaraRuleError("'of' set must not be empty")
        return ("of", quantifier, ids)


# ---------------------------------------------------------------------------
# Rule model + match evaluation
# ---------------------------------------------------------------------------


@dataclass
class YaraRule:
    name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: dict[str, tuple[str, Any, frozenset[str]]] = field(default_factory=dict)
    condition: Any = ("false",)

    def matches(self, data: bytes) -> bool:
        """Evaluate the rule condition against ``data``."""
        offsets = compute_offsets(self.strings, data)
        return bool(evaluate(self.condition, offsets))


def parse_rules(source: str) -> list[YaraRule]:
    """Parse one or more rules from ``source`` text."""
    return _Parser(_tokenize(source)).parse_rules()


def _variants(value: str, modifiers: frozenset[str]) -> list[tuple[bytes, bool]]:
    """Expand a text string into (needle, is_case_sensitive) search variants."""
    nocase = "nocase" in modifiers
    encodings: list[bytes] = []
    if "wide" in modifiers and "ascii" not in modifiers:
        encodings.append(value.encode("utf-16-le"))
    else:
        encodings.append(value.encode("utf-8"))
    if "wide" in modifiers:
        encodings.append(value.encode("utf-16-le"))
    return [(needle, not nocase) for needle in encodings]


def _is_word_char(byte: int) -> bool:
    return (65 <= byte <= 90) or (97 <= byte <= 122) or (48 <= byte <= 57) or byte in (95, 45)


def _search_text(
    data: bytes,
    needle: bytes,
    *,
    nocase: bool,
    fullword: bool,
) -> list[int]:
    haystack = data.lower() if nocase else data
    needle_lower = needle.lower() if nocase else needle
    offsets: list[int] = []
    start = 0
    while True:
        index = haystack.find(needle_lower, start)
        if index == -1:
            break
        if not fullword or (
            (index == 0 or not _is_word_char(haystack[index - 1]))
            and (
                index + len(needle_lower) >= len(haystack)
                or not _is_word_char(haystack[index + len(needle_lower)])
            )
        ):
            offsets.append(index)
        start = index + 1
    return offsets


def _parse_hex(elements: str) -> list[Any]:
    """Tokenize hex string content into byte/wildcard/jump elements."""
    parsed: list[Any] = []
    tokens = elements.replace(" ", "").lower()
    index = 0
    while index < len(tokens):
        char = tokens[index]
        if char == "?":
            if tokens[index : index + 2] != "??":
                raise YaraRuleError("hex wildcard must be '??'")
            parsed.append(("wild",))
            index += 2
            continue
        if char == "[":
            close = tokens.find("]", index)
            if close == -1:
                raise YaraRuleError("unterminated hex jump")
            body = tokens[index + 1 : close]
            if "-" in body:
                low_s, high_s = body.split("-", 1)
                low, high = int(low_s, 10), int(high_s, 10)
            else:
                low = high = int(body, 10)
            if low < 0 or high < low:
                raise YaraRuleError("invalid hex jump range")
            parsed.append(("jump", low, high))
            index = close + 1
            continue
        byte_text = tokens[index : index + 2]
        try:
            parsed.append(("byte", int(byte_text, 16)))
        except ValueError as exc:
            raise YaraRuleError(f"invalid hex byte {byte_text!r}") from exc
        index += 2
    return parsed


def _match_hex(data: bytes, position: int, elements: list[Any]) -> bool:
    if not elements:
        return True
    head = elements[0]
    kind = head[0]
    if kind == "byte":
        if position < len(data) and data[position] == head[1]:
            return _match_hex(data, position + 1, elements[1:])
        return False
    if kind == "wild":
        if position < len(data):
            return _match_hex(data, position + 1, elements[1:])
        return False
    low, high = head[1], head[2]
    return any(_match_hex(data, position + skip, elements[1:]) for skip in range(low, high + 1))


def _search_hex(data: bytes, content: str) -> list[int]:
    elements = _parse_hex(content)
    return [start for start in range(len(data)) if _match_hex(data, start, elements)]


def compute_offsets(
    strings: dict[str, tuple[str, Any, frozenset[str]]], data: bytes
) -> dict[str, list[int]]:
    """Compute match offsets for every defined string id against ``data``."""
    offsets: dict[str, list[int]] = {}
    for string_id, (kind, value, modifiers) in strings.items():
        if kind == "hex":
            offsets[string_id] = _search_hex(data, str(value))
            continue
        found: list[int] = []
        for needle, case_sensitive in _variants(str(value), modifiers):
            found.extend(
                _search_text(
                    data,
                    needle,
                    nocase=not case_sensitive,
                    fullword="fullword" in modifiers,
                )
            )
        offsets[string_id] = sorted(set(found))
    return offsets


def evaluate(condition: Any, offsets: dict[str, list[int]]) -> bool | int:
    """Evaluate a parsed condition AST given precomputed string offsets."""
    node = condition
    kind = node[0]

    if kind == "bool":
        return bool(node[1])
    if kind == "int":
        return int(node[1])
    if kind == "str":
        return bool(offsets.get(node[1]))
    if kind == "count":
        return len(offsets.get(node[1], []))
    if kind == "first":
        matches = offsets.get(node[1], [])
        return matches[0] if matches else 2**32 - 1
    if kind == "not":
        return not evaluate(node[1], offsets)
    if kind == "and":
        return evaluate(node[1], offsets) and evaluate(node[2], offsets)
    if kind == "or":
        return evaluate(node[1], offsets) or evaluate(node[2], offsets)
    if kind == "cmp":
        return _compare(node[1], evaluate(node[2], offsets), evaluate(node[3], offsets))
    if kind == "at":
        string_id = _string_ref(node[1])
        return evaluate(node[2], offsets) in offsets.get(string_id, [])
    if kind == "in":
        string_id = _string_ref(node[1])
        low = evaluate(node[2], offsets)
        high = evaluate(node[3], offsets)
        return any(low <= offset <= high for offset in offsets.get(string_id, []))
    if kind == "of":
        return _evaluate_of(node, offsets)
    raise YaraRuleError(f"unknown condition node: {node!r}")


def _string_ref(node: Any) -> str:
    if node[0] == "str":
        return str(node[1])
    raise YaraRuleError("'at'/'in' require a string reference on the left side")


def _evaluate_of(node: Any, offsets: dict[str, list[int]]) -> bool:
    quantifier = node[1]
    ids = node[2] or list(offsets)
    present = sum(1 for string_id in ids if offsets.get(string_id))
    if quantifier == "all":
        return present == len(ids)
    if quantifier == "any":
        return present > 0
    return present >= int(quantifier)


def _compare(op: str, left: Any, right: Any) -> bool:
    if op == "==":
        return bool(left == right)
    if op == "!=":
        return bool(left != right)
    if op == "<":
        return bool(left < right)
    if op == ">":
        return bool(left > right)
    if op == "<=":
        return bool(left <= right)
    if op == ">=":
        return bool(left >= right)
    raise YaraRuleError(f"unknown comparison operator {op!r}")
