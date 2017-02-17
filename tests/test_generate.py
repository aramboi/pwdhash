# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pwdhash

PASSWORD = "password12345"


def test_generate_domain():
    domain = "example.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "0JMBoaKI7NFhObN"

    domain = "google.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "YzvXOvv3tyZ0PIn"

    domain = "facebook.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "vYbDjKWA5RoWEWJ"


def test_generate_domain_includes_protocol():
    domain = "http://example.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "0JMBoaKI7NFhObN"

    domain = "https://google.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "YzvXOvv3tyZ0PIn"

    domain = "https://facebook.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "vYbDjKWA5RoWEWJ"


def test_generate_domain_includes_subdomain():
    domain = "http://bogus.example.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "0JMBoaKI7NFhObN"

    domain = "https://accounts.google.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "YzvXOvv3tyZ0PIn"

    domain = "https://www.facebook.com"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "vYbDjKWA5RoWEWJ"


def test_generate_domain_includes_query_params():
    domain = "http://bogus.example.com/path?test=test"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "0JMBoaKI7NFhObN"

    domain = "https://accounts.google.com/path/?test=test"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "YzvXOvv3tyZ0PIn"

    domain = "https://facebook.com/path?test=test"
    generated = pwdhash.generate(PASSWORD, domain)
    assert generated == "vYbDjKWA5RoWEWJ"


def test_generate_short_password():
    domain = "example.com"
    generated = pwdhash.generate("123", domain)
    assert generated == "7SXmR"


def test_polish_unicode_password():
    domain = "example.com"
    string = "Zażółć gęślą jaźń"
    generated = pwdhash.generate(string, domain)
    assert generated == "a3o9/S1NiAkwMr6BJzD"


def test_czech_unicode_password():
    domain = "example.com"
    string = "Příliš žluťoučký kůň úpěl ďábelské kódy"
    generated = pwdhash.generate(string, domain)
    assert generated == "ti+BTLNFRbS7vnJ5uFOs2w"


def test_hungarian_unicode_password():
    domain = "example.com"
    string = "Árvíztűrő tükörfúrógép"
    generated = pwdhash.generate(string, domain)
    assert generated == "jYNNgw1//znH8/aFIU19+g"


def test_if_prefix_is_trimmed():
    domain = "example.com"
    password = pwdhash.PASSWORD_PREFIX + PASSWORD
    generated = pwdhash.generate(password, domain)
    assert generated == "0JMBoaKI7NFhObN"
