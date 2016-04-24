#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import datetime

def replace_dt_hours(fromdatetime, hours):
    tz = fromdatetime.tzinfo
    return tz.normalize(datetime.datetime.combine(fromdatetime,
            datetime.time(tzinfo=tz)) + datetime.timedelta(hours=hours))

def daytime(dt, la, ln):
    timezone = dt.tzinfo
    offset = timezone.utcoffset(dt).total_seconds() / 240
    if timezone is None:
        raise ValueError("'dt' must have a tzinfo")
    a = 2 * math.pi * (dt.timetuple().tm_yday - 1) / 365
    phi = 0.006918 - 0.399912 * math.cos(a) + 0.070257 * math.sin(a) - \
          0.006758 * math.cos(2*a) + 0.000907 * math.sin(2*a) - \
          0.002697 * math.cos(3*a) + 0.001480 * math.sin(3*a)
    cosw0 = -math.tan(math.radians(la)) * math.tan(phi)
    if cosw0 > 1:
        return ()
    elif cosw0 < -1:
        return ((replace_dt_hours(dt, 0), replace_dt_hours(dt, 24)),)
    else:
        w0 = math.acos(cosw0)
        lt1 = math.degrees(-w0) / 15 + 12
        lt2 = math.degrees(w0) / 15 + 12
        t1 = (lt1 - (ln - offset) / 15 + 24) % 24
        t2 = (lt2 - (ln - offset) / 15 + 24) % 24
        if t1 < t2:
            return ((replace_dt_hours(dt, t1), replace_dt_hours(dt, t2)),)
        else:
            return ((replace_dt_hours(dt, 0), replace_dt_hours(dt, t2)),
                    (replace_dt_hours(dt, t1), replace_dt_hours(dt, 24)))

def midnight_delta(fromdatetime, adjust=True):
    fromtimestamp = fromdatetime.timestamp()
    midnight = datetime.datetime.combine(fromdatetime, 
        datetime.time(tzinfo=fromdatetime.tzinfo)).timestamp()
    delta = fromtimestamp - midnight
    if adjust and delta > 43200:
        return delta - 86400
    else:
        return delta

def is_day(dt, lat, lon):
    timezone = dt.tzinfo
    offset = timezone.utcoffset(dt).total_seconds() / 240
    clocktime = midnight_delta(dt, False) / 3600
    localtime = (clocktime + (lon-offset) / 15 + 24) % 24
    a = 2 * math.pi * (dt.timetuple().tm_yday - 1 + localtime / 24) / 365
    phi = 0.006918 - 0.399912 * math.cos(a) + 0.070257*math.sin(a) - \
          0.006758 * math.cos(2*a) + 0.000907 * math.sin(2*a) - \
          0.002697 * math.cos(3*a) + 0.001480 * math.sin(3*a)
    latrad = math.radians(lat)
    h0 = math.asin(math.cos(math.radians((localtime - 12) * 15)) *
            math.cos(latrad) * math.cos(phi) + math.sin(latrad) * math.sin(phi))
    return (h0 > 0)


if __name__ == '__main__':
    import pytz
    tz = pytz.timezone('Asia/Shanghai')
    print(daytime(datetime.datetime.now(tz), 31, 121))
    print(daytime(datetime.datetime.now(tz), 40.1522941, 116.264418999211))
    print(is_day(datetime.datetime.now(tz), 31, 121))
    print(is_day(datetime.datetime.now(tz), 40.1522941, 116.264418999211))
    tz = pytz.timezone('Asia/Tokyo')
    print(daytime(datetime.datetime.now(tz), 31, 121))
    print(daytime(datetime.datetime.now(tz), 40.1522941, 116.264418999211))
    print(is_day(datetime.datetime.now(tz), 31, 121))
    print(is_day(datetime.datetime.now(tz), 40.1522941, 116.264418999211))
