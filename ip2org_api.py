#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json

from bottle import route, run, Response
from ip2org import whois
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model import *

engine = create_engine("sqlite:///cache.db")
session = sessionmaker(bind=engine)()

Base.metadata.create_all(bind=engine, checkfirst=True)


@route("/<address>")
def ip2org_api(address):
    try:
        cache = session.query(Cache).filter(
            Cache.address==address
            ).all()
        ret = dict()
        if len(cache) > 0:
            cache = cache[0]
            ret.update({
                "ip": address,
                "company": cache.company,
                "ISP": cache.isp
                })
            print("Read from cache")
        else:
            result = whois(address)[0]
            ret.update({
                "ip": address,
                "company": result[result["org_key"]],
                "ISP": result[result["netname_key"]]
            })
            session.add(Cache(address=address,
                              company=ret["company"],
                              isp=ret["ISP"]))
            session.commit()
            print("Write to cache")
        return Response(
            json.dumps(ret, indent=2), 200
            )
    except ValueError as e:
        return Response(json.dumps({
            "error": str(e)
            }, indent=2), 500)

if __name__ == "__main__":
    run(host="localhost", port="5000")
