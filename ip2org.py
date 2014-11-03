#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from urllib.parse import urlparse

from IPy import IP
from telnetlib import Telnet

from decoder import *


server_map = {
    "arin": "whois.arin.net",
    "afrinic": "whois.afrinic.net",
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "twnic": "whois.twnic.net"
}


def whois(*iplist, **kwargs):
    ret = list()
    host = kwargs.get("host")
    port = kwargs.get("port") or 43

    ipv4_whois_list = list()
    ipv6_whois_list = list()

    # ip4_list and ip6_list have pairs of network range and
    # the corresponding whois server, however, need to de-serialize them.
    with open("ip4_list") as ipv4_file:
        ipv4_whois_list = list(
            map(lambda pair: [IP(pair[0]), pair[1]],
                decode_whoisList(ipv4_file.read()))
            )

    with open("ip6_list") as ipv6_file:
        ipv6_whois_list = list(
            map(lambda pair: [IP(pair[0]), pair[1]],
                decode_whoisList(ipv6_file.read()))
            )

    for ip_str in iplist:
        ip = IP(ip_str)
        if len(ip) != 1:
            raise ValueError(
                "The given IP address seems to be ranged IP address"
                )
        whoispair = list()
        if ip.version() == 4:
            for pair in ipv4_whois_list:
                if ip in pair[0]:
                    whoispair = pair
                    if host:
                        whoispair[1] = host
                    break
        elif ip.version() == 6:
            for pair in ipv6_whois_list:
                if ip in pair[0]:
                    if host:
                        whoispair[1] = host
                    break
        else:
            raise ValueError(("Unknown IP version: {0}").format(ip.version()))

        telnet = Telnet(
            server_map.get(whoispair[1]) or whoispair[1], port
        )
        if whoispair[1] != "whois.nic.ad.jp":
            telnet.write(("{0}\n").format(ip_str).encode("utf-8"))
        else:
            telnet.write(("{0}/e\n").format(ip_str).encode("utf-8"))
        result = telnet.read_all().decode("utf-8")
        telnet.close()
        del telnet

        if whoispair[1] in ["arin", server_map["arin"]]:
            result = decode_arin(result)
            ref = result.get("ReferralServer")
            # Sometimes, arin returns ReferralServer to redirect to the 
            # corresponding whois...
            if ref:
                parsed_url = urlparse(ref)

                (redirected_host, redirected_port) = \
                    parsed_url.netloc.split(":")
                result = whois(ip_str,
                               host=redirected_host,
                               port=redirected_port)
                if len(result) > 0:
                    result = result[0]
        elif whoispair[1] in ["apnic", server_map["apnic"]]:
            result = decode_apnic(result)
        elif whoispair[1] in ["afrinic", server_map["afrinic"]]:
            result = decode_afrinic(result)
        elif whoispair[1] in ["lacnic", server_map["lacnic"]]:
            result = decode_lacnic(result)
        elif whoispair[1] in ["ripe", server_map["ripe"]]:
            result = decode_ripe(result)
        elif whoispair[1] == "rwhois.gin.ntt.net":
            raise NotImplementedError("rwhois protocol is not supported")
        elif whoispair[1] == "twnic":
            raise ValueError("This NIC doesn't provide detailed information")
        elif whoispair[1] == "whois.nic.ad.jp":
            result = decode_jpnic(result)
        elif whoispair[1] == "whois.nic.ad.br":
            raise ValueError("This NIC shows illegal string")
        elif whoispair[1] == "whois.nic.or.kr":
            result = decode_krnic(result)
        # If there is no perser, add result as-is.
        ret.append(result)
    return ret


def ip2org(ip_fname, out_fname):
    ips = list()
    with open(ip_fname, "r") as f_in:
        ips = [line.rstrip() for line in f_in]
    data = whois(*ips)

    out = list()
    for infoIndex in range(0, len(data)):
        info = data[infoIndex]
        ip = ips[infoIndex]
        org_key = info.get("org_key")
        isp_key = info.get("netname_key")
        org = info.get(org_key, "") if org_key is not None else ""
        isp = info.get(isp_key, "") if isp_key is not None else ""
        out.append([ip, org, isp])

    with open(out_fname, "w+") as f_out:
        import csv
        writer = csv.writer(f_out)
        writer.writerows(out)


def main():
    import sys
    if len(sys.argv) != 3:
        print(("Usage: {0} [input file] [output file]").format(sys.argv[0]),
              file=sys.stderr)
        exit(1)
    ip2org(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
