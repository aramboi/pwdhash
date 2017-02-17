# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pwdhash
from nose_parameterized import parameterized

PASSWORD = "password12345"
TEST_PARAMETERS = (
    (
        "default_password_example_domain",
        PASSWORD, "example.com", "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_google_domain",
        PASSWORD, "google.com", "YzvXOvv3tyZ0PIn",
    ),
    (
        "default_password_facebook_domain",
        PASSWORD, "facebook.com", "vYbDjKWA5RoWEWJ",
    ),
    (
        "default_password_example_domain_with_protocol",
        PASSWORD, "http://example.com", "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_google_domain_with_protocol",
        PASSWORD, "https://google.com", "YzvXOvv3tyZ0PIn",
    ),
    (
        "default_password_facebook_domain_with_protocol",
        PASSWORD, "https://facebook.com", "vYbDjKWA5RoWEWJ",
    ),
    (
        "default_password_example_domain_with_subdomain",
        PASSWORD, "http://bogus.example.com", "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_google_domain_with_subdomain",
        PASSWORD, "https://accounts.google.com", "YzvXOvv3tyZ0PIn",
    ),
    (
        "default_password_facebook_domain_with_subdomain",
        PASSWORD, "https://www.facebook.com", "vYbDjKWA5RoWEWJ",
    ),
    (
        "default_password_example_domain_with_query_params",
        PASSWORD, "http://bogus.example.com/path?test=test",
        "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_google_domain_with_query_params",
        PASSWORD, "https://accounts.google.com/path/?test=test",
        "YzvXOvv3tyZ0PIn",
    ),
    (
        "default_password_facebook_domain_with_query_params",
        PASSWORD, "https://facebook.com/path?test=test", "vYbDjKWA5RoWEWJ",
    ),
    (
        "empty_password",
        "", "example.com", "2MPb",
    ),
    (
        "short_password",
        "123", "example.com", "7SXmR",
    ),
    (
        "polish_unicode_password",
        "Zażółć gęślą jaźń", "example.com", "a3o9/S1NiAkwMr6BJzD",
    ),
    (
        "czech_unicode_password",
        "Příliš žluťoučký kůň úpěl ďábelské kódy", "example.com",
        "ti+BTLNFRbS7vnJ5uFOs2w",
    ),
    (
        "hungarian_unicode_password",
        "Árvíztűrő tükörfúrógép", "example.com", "jYNNgw1//znH8/aFIU19+g",
    ),
    (
        "password_with_prefix",
        pwdhash.PASSWORD_PREFIX + PASSWORD, "example.com", "0JMBoaKI7NFhObN",
    ),

)


@parameterized.expand(TEST_PARAMETERS)
def test_should_generate_hash_for(_test_name, password, domain, expected):
    generated = pwdhash.generate(password, domain)
    assert generated == expected
