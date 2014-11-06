#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from sqlalchemy import Column, String, Text
from .base import Base


class Cache(Base):
    __tablename__ = "cache"
    address = Column(String(40), primary_key=True)
    company = Column(Text)
    isp = Column(Text)
