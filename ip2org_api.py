#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json

from bottle import route, run, Response
from ip2org import whois

@route("/<address>")
def ip2org_api(address):
    try:
        result = whois(address)[0]
        ret = {
            "ip": address,
            "company": result[result["org_key"]],
            "ISP": result[result["netname_key"]]
        }
        return Response(
            json.dumps(ret, indent=2), 200
            )
    except ValueError as e:
        return Response(json.dumps({
            "error": str(e)
            }, indent=2), 500)

if __name__ == "__main__":
    run(host="localhost", port="5000")
