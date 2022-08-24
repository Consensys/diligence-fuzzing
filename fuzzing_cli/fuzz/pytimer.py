#! /usr/bin/env python
## -*- coding: utf-8 -*-
################################################################
## Name: pytimer v0.0.1   Dec 12, 2011
## Notes: A sematic time string parser with handy timer functions
## Author: Howard Mei
## Email: howardleomei@gmail.com
## License: MIT, http://www.opensource.org/licenses/mit-license.php
################################################################

"""
  pytimer module implements various timing functions
  It has no external dependencies except for standard Python library.
  Usage:
  >>> from pytimer import str_to_time, time_to_str, dtime_it
  >>> str_to_time('1y 3mths 2w 5h 23mins 35s','ms')
  >>> 40675172492.432
  >>> time_to_str(451987987234,'us')
  >>> '0y 0mth 0w 5d 5h 33m 7s 987ms 234us'
  >>> @dtime_it('us')
  ... def repeat(n):
  ...    y = []
  ...    for i in xrange(n):
  ...       y.append(i*i+2*i+1)
  >>> repeat(100)
  >>> repeat@(122.13082 us)
  #Please explore other funcs/cls usage by yourself ^_^
"""
__version__ = "0.0.1"
__license__ = "The MIT License (MIT)"
__version_info__ = (0, 0, 1)
__author__ = "Howard Mei<howardleomei@gmail.com>"

import gc
import time
import timeit
from calendar import timegm
from datetime import datetime
from os import urandom

# It's for back conversion in time_to_str()
try:
    from collections import OrderedDict
except:
    pass

# Plan to enhance the default profiler, not implemented yet
try:
    from cProfile import Profile as _Profile
except ImportError:
    from profile import Profile as _Profile

import pstats as _ps

__all__ = [
    "dtime_it",
    "elapsedTime",
    "getStamp",
    "getUTC",
    "nowTimeStamp",
    "nowUTC",
    "parse_timestr",
    "str_to_micro",
    "str_to_mili",
    "str_to_sec",
    "str_to_time",
    "time_to_str",
    "timescale",
    "rid",
    "PTimer",
    "timeticker",
]


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


def str_to_sec(s):
    """ convert strings like "30d 12h" "1h 30m" "30m 5s" to seconds"""
    return long(str_to_time(s, "s"))


def str_to_mili(s):
    """ convert strings like "5d 1h 3m" "1h" "30m" to milliseconds"""
    return long(str_to_time(s, "ms"))


def str_to_micro(s):
    """ convert strings like "5d" "1h" "30m" to microseconds"""
    return long(str_to_time(s, "us"))


def time_to_str(t, ounit="us"):
    """ Convert time back to string """
    if not t:
        print("Please specify time and unit.")
        return
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
    for k in d:
        p = t * timescale(ounit, k)
        d[k] = int(p) * 1.0
        t = t - d[k] * timescale(k, ounit)
    tstr = ""
    for u, v in d.items():
        tstr += str(int(v)) + str(u) + " "
    return tstr


## end of str-time converters, following funcs are timers related:


def nowUTC():
    """
    Returns the current time UTC object
    """
    return datetime.utcnow()


def nowTimeStamp(unit="us"):
    """
    Returns a long integer representing UTC timestamp in 'us','ms','s'
    Generate identical outputs across platforms
    """
    unit = _unify(unit)
    if unit == "s":
        return long(time.time())
    elif unit == "ms":
        return long(time.time() * 1000.0)
    elif unit == "us":
        return long(
            time.time() * 1000.0 * 1000.0
            + (time.clock() * 1000.0 - int(time.clock() * 1000.0)) * 1000.00
        )
    else:
        raise TypeError("Not supported timestamp unit:", unit)


def getStamp(timeutc, unit="us"):
    """
    Convert UTC datetime to long integer timestamp in micro/mili.seconds
    usage: getStamp(utctime,unit='us') # unit could be 'us','ms','s'
    """
    if isinstance(timeutc, datetime):
        unit = _unify(unit)
        if unit == "s":
            return long(timegm(timeutc.utctimetuple()))
        elif unit == "ms":
            return long(
                timegm(timeutc.utctimetuple()) * 1000.0 + timeutc.microsecond / 1000.0
            )
        elif unit == "us":
            return long(
                timegm(timeutc.utctimetuple()) * 1000000.0 + timeutc.microsecond
            )
        else:
            raise TypeError("Not supported timestamp unit:" + unit)
    else:
        raise TypeError("Unknow timeutc type:", timeutc, ".Use UTC time to retry.")


def getUTC(timestamp, tsunit="us"):
    """
    Convert long integer timestamp back to UTC time
    usage: getUTC(1423534523L,tsunit='us') # unit could be 'us','ms','s'
    e.g. _epoch=getUTC(0L)
    """
    tsunit = _unify(tsunit)
    if tsunit not in ("us", "ms", "s"):
        raise TypeError("Incorrect timestamp unit:", tsunit)

    if isinstance(timestamp, long):
        return datetime.utcfromtimestamp(timestamp * timescale(tsunit, "s"))
    else:
        raise TypeError("Unknow timestamp:", timestamp, "Use timestamp to retry.")


def elapsedTime(origt=None, ounit="us", unit="us"):
    """
    Check elapsed time via timestamp or utc time.
    """
    if not origt:
        print("Please specify original utc time or time stamp")
        return

    if isinstance(origt, long):
        if ounit != unit:
            scale = timescale(ounit, unit)
            if scale > 1:
                print("Low precision Timestamp cannot get high precision delta")
        else:
            scale = 1.0
        delta = (nowTimeStamp(ounit) - origt) * scale
        return delta
    elif isinstance(origt, datetime):
        delta = nowUTC() - origt
        return float(
            delta.seconds * timescale("s", unit)
            + delta.microseconds * timescale("us", unit)
        )


def dtime_it(unit="us", type=0):  # universal for various platforms, recommended to use
    if type == 0:
        timer = timeit.default_timer
        scale = timescale("s", unit)
    else:
        timer = nowTimeStamp
        scale = timescale("us", unit)
    if not isinstance(unit, str):
        raise KeyError(
            'dtime_it should be used as a functional decorator: @dtime_it() or @dtime_it(unit="us")'
        )
    unit = _unify(unit)

    def outer(function):
        def wrapper(*args):
            start = timer()
            r = function(*args)
            end = timer()
            print("%s@(%0.5f %s)" % (function.func_name, (end - start) * scale, unit))
            return r

        return wrapper

    return outer


def rid(
    n=12
):  ## could only generate 2, 4, 6, ... even numbers of string using hex encoding
    """Get a random id hex string."""
    if not isinstance(n, int):
        raise ValueError("rid only takes int as output string length argument")
    if n < 6 or n > 60:
        raise ValueError("n should be in the range of 6~60")
    return urandom(n / 2).encode("hex")


def tupleTS(unit="us"):
    """Return a timestamp tuple similar to os.times()"""
    return (float(nowTimeStamp(unit)), 0.0, 0.0, 0.0, 0.0)


class PTimer:
    """
    A cross-platform timer class with advanced timing features.
    """

    def __init__(
        self,
        name=None,
        timerid=None,
        timer=None,
        disable_gc=False,
        precision="us",
        verbose=True,
    ):
        self.name = str(name)
        if timerid is None:
            self.tid = rid(6)
        else:
            self.tid = str(timerid)
        if timer is None:
            timer = timeit.default_timer
        self.timer = timer
        self.disable_gc = disable_gc
        self.unit = precision
        self._scale = timescale("s", precision)
        self.verbose = verbose
        self.start = self.end = self.interval = None

    def __enter__(self):
        if self.verbose:
            sn = self.name if self.name else self.tid
            print("--->%s Timer start: 0.00 %s<---" % (sn, self.unit))
        if self.disable_gc:
            self.gc_state = gc.isenabled()
            gc.disable()
        self.start = self.timer()
        return self

    def __exit__(self, *args):
        self.end = self.timer()
        if self.disable_gc and self.gc_state:
            gc.enable()
        self.interval = self.end * self._scale - self.start * self._scale
        if self.verbose:
            sn = self.name if self.name else self.tid
            print("--->%s Timer end: %f %s<---" % (sn, self.interval, self.unit))


def timeticker(name=None, unit="us"):
    _ticker = PTimer(name=name, precision=unit)  # get an instance of PTimer
    return _ticker


def time_out(str):
    """
    Set time out for a function to disrupt the execution of any code
    """
    pass


# def _warmup(n=1):
#     if n<1:
#         return
#     for i in range(n):
#         urandom(6)   ## run it to speed up future calls
#         rid(6)  ## run it to speed up future calls
#
#
# _warmup(1)
