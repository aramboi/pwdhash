# -*- coding: utf-8 -*-
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


def test_generate_short_password():
    domain = "example.com"
    generated = pwdhash.generate('123', domain)
    assert generated == "7SXmR"
