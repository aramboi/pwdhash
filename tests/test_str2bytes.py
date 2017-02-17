# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pwdhash


def test_ascii_string():
    string = "some simple ascii"
    expected = b'some simple ascii'
    assert pwdhash.str2bytes(string) == expected


def test_polish_unicode_string():
    string = "Zażółć gęślą jaźń"
    expected = b'Za|\xf3B\x07 g\x19[l\x05 jazD'
    assert pwdhash.str2bytes(string) == expected


def test_czech_unicode_string():
    string = "Příliš žluťoučký kůň úpěl ďábelské"
    expected = b'PY\xedlia ~lueou\rk\xfd koH \xfap\x1bl \x0f\xe1belsk\xe9'
    assert pwdhash.str2bytes(string) == expected


def test_hungarian_unicode_string():
    string = "Árvíztűrő tükörfúrógép"
    expected = b'\xc1rv\xedztqrQ t\xfck\xf6rf\xfar\xf3g\xe9p'
    assert pwdhash.str2bytes(string) == expected
