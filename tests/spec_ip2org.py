#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from nose.tools import *
from nose.plugins.skip import SkipTest
from ip2org import whois


@raises(ValueError)
def test_no_domains():
    # This should raise ValueError because
    # ip2org doesn't support domain search.
    whois("google.com")


@raises(ValueError)
def test_invalid_ip():
    # This also should raise ValueError because the given
    # IP address is invalid.
    ips = ["256.0.0.0", "0.256.0.0", "0.0.256.0", "0.0.0.256"]
    whois(*ips)


@raises(ValueError)
def test_range():
    # ip range with /XX is not desired.
    ip = "192.168.100.0/24"
    whois(ip)


def test_empty():
    result = whois()
    assert_equal(len(result), 0, "The length of reuslt should be 0")


def test_google():
    # Google IP Addresses are managed by arin.
    ip = [
        "173.194.38.0", "173.194.38.1", "173.194.38.2", "173.194.38.3",
        "173.194.38.4", "173.194.38.5", "173.194.38.6", "173.194.38.7",
        "173.194.38.8", "173.194.38.9", "173.194.38.14"
        ]

    result = whois(*ip)
    assert_equal(len(result), len(ip),
                 "The number of the result should be the same of the # of ips."
                 )

    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    origin_list = list(map(lambda e: e.get("whois"), result))
    for name in orgnames:
        assert_equal(name, "Google Inc. (GOGL)",
                     "name should be Google Inc. (GOGL).")
    for origin in origin_list:
        assert_equal(origin, "arin", "origin should be arin")


def test_apnic():
    apnic = ["27.114.150.10", "27.114.150.11", "27.114.150.12"]
    result = whois(*apnic)
    from pprint import pprint
    pprint(result)
    assert_equal(len(result), len(apnic),
                 "The number of result should be the same of the # of asia."
                 )

    origin_list = list(map(lambda e: e.get("whois"), result))
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    for origin in origin_list:
        assert_equal(origin, "apnic", "origin should be apnic")

    for name in orgnames:
        assert_equal(name,
                     "Dhivehi Raajjeyge Gulhun (PRIVATE LIMITED)",
                     ("name should be"
                         "Dhivehi Raajjeyge Gulhun (PRIVATE LIMITED)"))


def test_afrinic():
    afrinic = ["146.231.129.86", "41.248.247.207",
               "146.231.129.81", "197.80.150.123"]
    organizations = [
        "Rhodes University", None, "Rhodes University",
        "MWEB CONNECT (PROPRIETARY) LIMITED"
        ]
    result = whois(*afrinic)
    origin_list = list(map(lambda e: e.get("whois"), result))
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    for origin in origin_list:
        assert_equal(origin, "afrinic", "origin should be afrinic")

    assert_list_equal(orgnames, organizations)


def test_lacnic():
    lanic = [
        "200.89.75.197", "200.89.75.198",
        "190.15.141.64", "200.1.19.4"
        ]
    organizations = [
        "Universidad de Chile",
        "Universidad de Chile",
        "CEDIA",
        "Universidad Tecnica Federico Santa Maria"
        ]
    result = whois(*lanic)
    origin = set(list(map(lambda el: el.get("whois"), result)))
    assert_equal(len(origin), 1)
    assert_list_equal(list(origin), ["lancic"])
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    assert_list_equal(orgnames, organizations)


def test_ripe():
    ripe = [
        "5.34.248.224", "94.23.166.108",
        "213.95.21.43", "188.138.75.207"
        ]
    organizations = [
        "Newsnet AG",
        "OVH GmbH",
        None,
        None
    ]
    result = whois(*ripe)
    origin = set(list(map(lambda el: el.get("whois"), result)))
    assert_equal(len(origin), 1)
    assert_list_equal(list(origin), ["ripe"])
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    assert_list_equal(orgnames, organizations)


@raises(NotImplementedError)
def test_rwhois_ntt():
    ntt = ["204.0.0.2", "204.1.1.25"]
    whois(*ntt)

@raises(ValueError)
def test_twnic():
    twnic = ["202.39.128.5", "202.39.238.192"]
    whois(*twnic)


def test_jpnic():
    jpnic = ["211.120.0.3", "211.130.5.1", "211.125.255.230"]
    organizations = [
        "Yahoo Japan Corporation",
        "F Bit Communications Corp.",
        "Oita Cable Telecom Co,.Ltd."
        ]
    result = whois(*jpnic)
    origin = set(list(map(lambda el: el.get("whois"), result)))
    assert_equal(len(origin), 1)
    assert_list_equal(list(origin), ["whois.nic.ad.jp"])
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    assert_list_equal(orgnames, organizations)


@raises(ValueError)
def test_brnic():
    brnic = ["200.17.0.5"]
    whois(*brnic)


def test_krnic():
    krnic = ["222.122.0.5", "222.122.10.30", "222.122.130.45"]
    organizations = [
        "Korea Telecom",
        "Korea Telecom",
        "Korea Telecom"
        ]

    result = whois(*krnic)
    origin = set(list(map(lambda el: el.get("whois"), result)))
    assert_equal(len(origin), 1)
    assert_list_equal(list(origin), ["whois.nic.or.kr"])
    orgnames = list(map(lambda e: e.get(e["org_key"]), result))
    assert_list_equal(orgnames, organizations)
