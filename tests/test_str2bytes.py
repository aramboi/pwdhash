# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pwdhash
from nose_parameterized import parameterized


TEST_PARAMETERS = (
    (
        "ascii_string",
        "some simple ascii", b'some simple ascii',
    ),
    (
        "polish_unicode_string",
        "Zażółć gęślą jaźń", b'Za|\xf3B\x07 g\x19[l\x05 jazD',
    ),
    (
        "czech_unicode_string",
        "Příliš žluťoučký kůň úpěl ďábelské",
        b'PY\xedlia ~lueou\rk\xfd koH \xfap\x1bl \x0f\xe1belsk\xe9',
    ),
    (
        "hungarian_unicode_string",
        "Árvíztűrő tükörfúrógép",
        b'\xc1rv\xedztqrQ t\xfck\xf6rf\xfar\xf3g\xe9p',
    ),
)


@parameterized.expand(TEST_PARAMETERS)
def test_should_encode(_test_name, string_to_encode, expected_bytes):
    assert pwdhash.str2bytes(string_to_encode) == expected_bytes
