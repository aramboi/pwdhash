# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pwdhash
from nose_parameterized import parameterized

PASSWORD = "password12345"
DOMAIN = "example.com"
TEST_PARAMETERS = (
    (
        "default_password_example_domain",
        PASSWORD, DOMAIN, "0JMBoaKI7NFhObN",
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
        "empty_password",
        "", DOMAIN, "2MPb",
    ),
    (
        "short_password",
        "123", DOMAIN, "7SXmR",
    ),
    (
        "polish_unicode_password",
        "Zażółć gęślą jaźń", DOMAIN, "a3o9/S1NiAkwMr6BJzD",
    ),
    (
        "czech_unicode_password",
        "Příliš žluťoučký kůň úpěl ďábelské kódy", DOMAIN,
        "ti+BTLNFRbS7vnJ5uFOs2w",
    ),
    (
        "hungarian_unicode_password",
        "Árvíztűrő tükörfúrógép", DOMAIN, "jYNNgw1//znH8/aFIU19+g",
    ),
    (
        "password_with_prefix",
        pwdhash.PASSWORD_PREFIX + PASSWORD, DOMAIN, "0JMBoaKI7NFhObN",
    ),
    # check if generate() has extract_domain attached (to work as standalone)
    (
        "default_password_example_domain_with_protocol",
        PASSWORD, "http://{}".format(DOMAIN), "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_example_domain_with_subdomain",
        PASSWORD, "http://bogus.{}".format(DOMAIN), "0JMBoaKI7NFhObN",
    ),
    (
        "default_password_example_domain_with_query_params",
        PASSWORD, "http://bogus.{}/path?test=test".format(DOMAIN),
        "0JMBoaKI7NFhObN",
    ),

)


@parameterized.expand(TEST_PARAMETERS)
def test_should_generate_hash_for(_test_name, password, domain, expected):
    generated = pwdhash.generate(password, domain)
    assert generated == expected
