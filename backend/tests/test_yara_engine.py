"""Unit tests for the pure-Python YARA-subset engine (Phase 9)."""

from __future__ import annotations

import pytest
from app.services.detection.yara_engine import YaraRuleError, parse_rules


def _rule(source: str, index: int = 0):
    return parse_rules(source)[index]


class TestParse:
    def test_rule_shape(self) -> None:
        rule = _rule(
            r"""
rule win_malware : trojan { 
meta:
  description = "sample"
  score = 3
  enabled = true
strings:
  $a = "evil"
condition:
  $a
}
"""
        )
        assert rule.name == "win_malware"
        assert rule.tags == ["trojan"]
        assert rule.meta == {"description": "sample", "score": 3, "enabled": True}
        assert rule.strings == {"$a": ("text", "evil", frozenset())}

    def test_multiple_rules(self) -> None:
        rules = parse_rules(
            r"""
rule first { condition: true }
rule second { condition: false }
"""
        )
        assert [r.name for r in rules] == ["first", "second"]

    def test_comments_stripped(self) -> None:
        rule = _rule(
            r"""
// line comment
rule with_comments {
  /* block comment
     spanning lines */
  strings:
    $a = "x" // trailing
  condition:
    $a
}
"""
        )
        assert rule.strings["$a"] == ("text", "x", frozenset())

    def test_hex_string(self) -> None:
        rule = _rule(r"""rule hex { strings: $a = { 4D 5A ?? 90 [1-3] } condition: $a }""")
        assert rule.strings["$a"][0] == "hex"

    def test_escaped_string(self) -> None:
        rule = _rule(r"""rule esc { strings: $a = "a\n\"b\\c" condition: $a }""")
        assert rule.strings["$a"][1] == 'a\n"b\\c'

    def test_import_rejected(self) -> None:
        with pytest.raises(YaraRuleError, match="not supported"):
            parse_rules(r'''import "pe"''')

    def test_string_literal_in_condition_rejected(self) -> None:
        with pytest.raises(YaraRuleError, match="string literal"):
            parse_rules(r"""rule bad { condition: "abc" }""")

    def test_unknown_character_rejected(self) -> None:
        with pytest.raises(YaraRuleError):
            parse_rules(r"""rule bad { condition: true ; }""")

    def test_unterminated_comment_rejected(self) -> None:
        with pytest.raises(YaraRuleError, match="unterminated block comment"):
            parse_rules(r"""rule bad { /* nope """)


class TestTextMatching:
    def test_basic(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "evil" condition: $a }""")
        assert rule.matches(b"nothing evil here")
        assert not rule.matches(b"clean")

    def test_nocase(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "Evil" nocase condition: $a }""")
        assert rule.matches(b"EVIL")
        assert rule.matches(b"evil")

    def test_wide(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "evil" wide condition: $a }""")
        assert rule.matches("evil".encode("utf-16-le"))

    def test_fullword(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "root" fullword condition: $a }""")
        assert rule.matches(b"root")
        assert rule.matches(b"the root user")
        assert not rule.matches(b"rootkit")

    def test_ascii_and_wide(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "evil" ascii wide condition: $a }""")
        assert rule.matches(b"evil")
        assert rule.matches("evil".encode("utf-16-le"))


class TestHexMatching:
    def test_bytes_and_wildcard(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { 01 ?? 03 } condition: $a }""")
        assert rule.matches(bytes([0, 0, 1, 0xFE, 3]))
        assert not rule.matches(bytes([0, 1, 2]))

    def test_fixed_jump(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { 01 [2] 02 } condition: $a }""")
        assert rule.matches(bytes([1, 9, 9, 2]))
        assert not rule.matches(bytes([1, 9, 2]))

    def test_range_jump(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { 01 [1-3] 02 } condition: $a }""")
        assert rule.matches(bytes([1, 9, 9, 9, 2]))
        assert not rule.matches(bytes([1, 9, 9, 9, 9, 2]))

    def test_empty_hex_is_vacuous(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { } condition: $a }""")
        assert rule.matches(b"anything")


class TestCondition:
    def test_bool_constants(self) -> None:
        assert parse_rules(r"""rule r { condition: true }""")[0].matches(b"")
        assert not parse_rules(r"""rule r { condition: false }""")[0].matches(b"")

    def test_not(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "x" condition: not $a }""")
        assert rule.matches(b"clean")
        assert not rule.matches(b"x")

    def test_or_and(self) -> None:
        rule = _rule(
            r"""
rule r {
  strings:
    $a = "alpha"
    $b = "beta"
    $c = "gamma"
  condition:
    ($a and $b) or $c
}
"""
        )
        assert rule.matches(b"alpha beta")
        assert rule.matches(b"gamma")
        assert not rule.matches(b"alpha delta")

    def test_at(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "GET" condition: $a at 0 }""")
        assert rule.matches(b"GET / HTTP/1.1")
        assert not rule.matches(b"xx GET")

    def test_in_range(self) -> None:
        rule = _rule(
            r"""
rule r {
  strings:
    $a = "start"
    $b = "end"
  condition:
    $b in (10..20)
}
"""
        )
        assert rule.matches(b"start" + b"x" * 6 + b"end")
        assert not rule.matches(b"start" + b"x" * 30 + b"end")

    def test_count_comparison(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "x" condition: #a == 2 }""")
        assert rule.matches(b"x y x")
        assert not rule.matches(b"x y")

    def test_first_offset(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "x" condition: @a == 0 }""")
        assert rule.matches(b"x first")
        assert not rule.matches(b" first x")

    def test_any_of_them(self) -> None:
        rule = _rule(
            r"""
rule r {
  strings:
    $a = "alpha"
    $b = "beta"
  condition:
    any of them
}
"""
        )
        assert rule.matches(b"alpha")
        assert rule.matches(b"beta")
        assert not rule.matches(b"gamma")

    def test_all_of_set(self) -> None:
        rule = _rule(
            r"""
rule r {
  strings:
    $a = "a1"
    $b = "b1"
  condition:
    all of ($a, $b)
}
"""
        )
        assert rule.matches(b"a1 b1")
        assert not rule.matches(b"a1 only")

    def test_two_of_set(self) -> None:
        rule = _rule(
            r"""
rule r {
  strings:
    $a = "a1"
    $b = "b1"
    $c = "c1"
  condition:
    2 of ($a, $b, $c)
}
"""
        )
        assert rule.matches(b"a1 c1")
        assert not rule.matches(b"a1 only")

    def test_comparison_on_count(self) -> None:
        rule = _rule(r"""rule r { strings: $a = "x" condition: #a >= 1 }""")
        assert rule.matches(b"x")


class TestErrors:
    def test_expected_rule(self) -> None:
        with pytest.raises(YaraRuleError, match="expected 'rule'"):
            parse_rules(r"""not_a_rule {}""")

    def test_invalid_hex_byte(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { ZZ } condition: $a }""")
        with pytest.raises(YaraRuleError):
            rule.matches(b"\x00")

    def test_hex_wildcard_partial_rejected(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { 4D ?M } condition: $a }""")
        with pytest.raises(YaraRuleError, match="wildcard"):
            rule.matches(b"\x00")

    def test_bad_jump_range(self) -> None:
        rule = _rule(r"""rule r { strings: $a = { 4D [5-2] 90 } condition: $a }""")
        with pytest.raises(YaraRuleError, match="jump range"):
            rule.matches(b"\x00")
