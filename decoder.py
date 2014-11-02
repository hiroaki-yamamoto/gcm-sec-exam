#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

import yaml


def decode_whoisList(read_str):
    '''
    This function scrapes IP range and whois server from ip4_list and ip6_list
    '''
    list_per_line = read_str.split("\n")
    list_removed_line_comment = list(
        filter(lambda el: len(el) > 0 and el[0] != "#", list_per_line)
        )
    split_delim = re.compile("(\s+)")
    ip_info_pairs = list(map(lambda el: split_delim.split(el),
                             list_removed_line_comment))
    for ip_index in range(0, len(ip_info_pairs)):
        ip_info_pairs[ip_index] = list(
            filter(lambda el: not split_delim.match(el),
                   ip_info_pairs[ip_index])
            )
    ip_info_pairs = list(map(lambda el: [el[0], el[1]], ip_info_pairs))
    return ip_info_pairs


def whois_yaml_like(telnet_result, comment_pattern=None):
    lines = telnet_result.split("\n")
    if comment_pattern:
        comment = re.compile(comment_pattern)
        lines = list(filter(lambda line: not comment.match(line), lines))
    for line_index in range(0, len(lines)):
        line = lines[line_index]
        if ":" not in line:
            continue
        parsed_line = line.split(":", 1)
        parsed_line[1] = ("\"{0}\"").format(parsed_line[1].strip())
        lines[line_index] = (": ").join(parsed_line)
    removed_comment = ("\n").join(lines)
    result = yaml.safe_load(removed_comment)
    return result


def decode_arin(telnet_result):
    ret = whois_yaml_like(telnet_result, "^(Comment)")
    ret["whois"] = "arin"
    ret["org_key"] = "Organization"
    ret["netname_key"] = "NetName"
    return ret


def decode_apnic(telnet_result):
    ret = whois_yaml_like(telnet_result, "^(remarks|%)")
    ret["whois"] = "apnic"
    ret["org_key"] = "descr"
    ret["netname_key"] = "netname"
    return ret


def decode_afrinic(telnet_result):
    ret = whois_yaml_like(telnet_result, "^(remarks|%)")
    ret["whois"] = "afrinic"
    ret["org_key"] = "org-name"
    ret["netname_key"] = "netname"
    return ret


def decode_lacnic(telnet_result):
    ret = whois_yaml_like(telnet_result, "^(remarks|%)")
    ret["whois"] = "lancic"
    ret["org_key"] = "owner"
    return ret


def decode_ripe(telnet_result):
    ret = whois_yaml_like(telnet_result, "^(remarks|%)")
    ret["whois"] = "ripe"
    ret["org_key"] = "org-name"
    ret["netname_key"] = "netname"
    return ret


def decode_jpnic(telnet_result):
    pattern = re.compile("^([a-z]+\.\s+)*\[(.+)\]\s+(.+)$")
    lines = telnet_result.split("\n")
    lines = list(map(lambda el: el.strip(), lines))
    lines = lines[lines.index("Network Information:")+1:]

    ret = {}
    for line in lines:
        if pattern.match(line):
            parsed = pattern.split(line)
            if len(parsed) > 3:
                ret[parsed[2]] = parsed[3]
            else:
                ret[parsed[2]] = None
    ret["whois"] = "whois.nic.ad.jp"
    ret["org_key"] = "Organization"
    ret["netname_key"] = "Network Name"
    return ret


def decode_krnic(telnet_result):
    lines = telnet_result.split("\n")
    begin = None
    end = None

    for line_index in range(0, len(lines)):
        line = lines[line_index].strip()
        if line == "[ Network Information ]":
            if begin is None:
                begin = line_index+1
        if begin is not None and line == "[ Admin Contact Information ]":
            end = line_index - 2

    lines = lines[begin:end]
    lines = ("\n").join(lines)
    ret = whois_yaml_like(lines)
    ret["whois"] = 'whois.nic.or.kr'
    ret["org_key"] = "Organization Name"
    ret["netname_key"] = "Service Name"
    return ret

if __name__ == "__main__":
    from pprint import pprint
    ipv4_str = None
    with open("ip4_list") as f_in:
        ipv4_str = f_in.read()
    ipv4_list = decode_whoisList(ipv4_str)
    print("IPv4 Whois pairs:")
    pprint(ipv4_list)
    print("Unique whois server list:")
    pprint(set(list(map(lambda el: el[1], ipv4_list))))

    print("\n")

    ipv6_str = None
    with open("ip6_list") as f_in:
        ipv6_str = f_in.read()

    ipv6_list = decode_whoisList(ipv6_str)
    pprint(ipv6_list)
    print("Unique whois server list:")
    pprint(set(list(map(lambda el: el[1], ipv6_list))))
