#! /usr/bin/env python
## -*- coding: utf-8 -*-
################################################################
## Name: pytimer v0.0.1   Dec 12, 2011
## Notes: A sematic time string parser with handy timer functions
## Author: Howard Mei
## Email: howardleomei@gmail.com
## License: MIT, http://www.opensource.org/licenses/mit-license.php
################################################################
__version__ = "0.0.1"
__license__ = "The MIT License (MIT)"
__version_info__ = (0, 0, 1)
__author__ = "Howard Mei<howardleomei@gmail.com>"

from collections import OrderedDict

__all__ = ["parse_timestr", "str_to_sec", "str_to_time", "timescale"]


def _unify(ounit="sec"):
    """
    Return unified time unit.
    """
    ounit = ounit.lower()
    if ounit in ("y", "year", "yrs", "years"):
        return "y"
    elif ounit in ("mth", "mths", "month", "months"):
        return "mth"
    elif ounit in ("w", "wks", "week", "weeks"):
        return "w"
    elif ounit in ("d", "day", "days"):
        return "d"
    elif ounit in ("h", "hour", "hr", "hrs", "hours"):
        return "h"
    elif ounit in ("m", "min", "mins", "minutes"):
        return "m"
    elif ounit in ("s", "sec", "secs", "seconds"):
        return "s"
    elif ounit in ("ms", "milliseconds"):
        return "ms"
    elif ounit in ("us", "microseconds"):
        return "us"
    else:
        raise TypeError("Unknown time unit:", ounit)


def timescale(src="hr", dst="sec"):
    """
    Return a scale number between two time units.
    """
    ruler = {
        "d": 86400000000.0,
        "h": 3600000000.0,
        "m": 60000000.0,
        "s": 1000000.0,
        "ms": 1000.0,
        "us": 1.0,
    }
    ruler["w"] = 7.0 * ruler["d"]
    ruler["mth"] = 30.436849917 * ruler["d"]
    ruler["y"] = 12.0 * ruler["mth"]
    return ruler[_unify(src)] / ruler[_unify(dst)]


def parse_timestr(s):
    """
    parse time strings to dict with separated units(up to day):
    >>>parse_timestr('5d 3h 50m 15s 20ms 6us')
    {'d':5, 'h':3, 'm':50, 's':15, 'ms':20, 'us':6}
    >>>parse_timestr('5day')  # or '5days'
    {'d':5, 'h':0.0, 'm':0.0, 's':0.0, 'ms':0.0, 'us':0.0}
    >>>parse_timestr('24hrs,30mins')
    {'h':24, 'm':30,'m':0.0, 's':0.0, 'ms':0.0, 'us':0.0}
    """
    if not s:
        print("Please specify time string.")
        return
    if not OrderedDict:
        raise ValueError("Need OrderedDict support if Python ver<2.7")
    d = OrderedDict(
        [
            ("y", 0.0),
            ("mth", 0.0),
            ("w", 0.0),
            ("d", 0.0),
            ("h", 0.0),
            ("m", 0.0),
            ("s", 0.0),
            ("ms", 0.0),
            ("us", 0.0),
        ]
    )
    s = str(s).replace(",", " ")
    ss = s.split(" ")
    for s in ss:
        value = "".join([c for c in s if c.isdigit()])
        if not value:
            raise ValueError("Missing time digits:", s)
        unit = _unify(s.strip(value))
        d[unit] = value
    return d


def str_to_time(s, unit="us"):
    """
    Convert any time string like: '5d 3h 50m 15s 20ms 6us' to specified unit
    returning a float number.
    """
    if not isinstance(s, str):
        print("Please specify a time string")
        return
    d = parse_timestr(s)
    res = 0
    for u, v in d.items():
        res += float(v) * timescale(u, unit)
    return res


def str_to_sec(s) -> float:
    """convert strings like "30d 12h" "1h 30m" "30m 5s" to seconds"""
    return str_to_time(s, "s")
