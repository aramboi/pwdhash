# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pwdhash
from nose_parameterized import parameterized

DOMAINS_TO_CHECK = (
    "a.pl", "example.com", "example.gov.sg", "two-words42.cnt.br"
)
TEST_CONDITIONS = (
    ("already_clean_domain", "{}"),
    ("domain_with_protocol", "http://{}"),
    ("domain_with_secure_protocol", "https://{}"),
    ("domain_with_protocol_and_slash", "http://{}/"),
    ("domain_with_document", "http://{}/index.html"),
    ("domain_with_subdomain", "http://subdomain.{}/"),
    ("domain_with_path", "http://{}/path/to/site/"),
    ("domain_with_query_params", "http://{}/?age=20"),
    ("domain_with_path_query_params", "http://{}/path/?age=20"),
)


@parameterized.expand(TEST_CONDITIONS)
def test_should_extract_domain_from(_test_name, tested_fmt):
    for domain in DOMAINS_TO_CHECK:
        assert pwdhash.extract_domain(tested_fmt.format(domain)) == domain
