#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Trusted Sleep Monitor Bot

This bot monitors group members' sleep time using online status.

Threads:
* tg-cli
  * Event: set online state
* Telegram API polling
  * /status - List sleeping status (group only)
  * /list - List stats about sleep time (group only)
  * /help - About the bot
  * /start - Describe how to use
  * /settz - Set user timezone
  * /subscribe - Add user to watchlist
  * /unsubscribe - Remove user from watchlist
* Main
  * Status dict
    * Member
      * Basic info
      * Subscribed?
      * Timezone
    * Chat Group
    * Sleep start/end events

STATE = {
    # subscribed users
    "users": {id: {<tg-formatted object>}},
    "events": {id: [<unix timestamps>]},
    "status": {}
}

'''


import os
import re
import sys
import time
import json
import socket
import logging
import datetime
import requests
import itertools
import threading

import pytz
import tgcli

logging.basicConfig(stream=sys.stderr, format='%(asctime)s [%(name)s:%(levelname)s] %(message)s', level=logging.DEBUG if sys.argv[-1] == '-v' else logging.INFO)

logger_botapi = logging.getLogger('botapi')

class AttrDict(dict):

    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

# API bot

HSession = requests.Session()


class BotAPIFailed(Exception):
    pass


def bot_api(method, **params):
    for att in range(3):
        try:
            req = HSession.get(('https://api.telegram.org/bot%s/' %
                                CFG.apitoken) + method, params=params, timeout=45)
            retjson = req.content
            ret = json.loads(retjson.decode('utf-8'))
            break
        except Exception as ex:
            if att < 1:
                time.sleep((att + 1) * 2)
            else:
                raise ex
    if not ret['ok']:
        raise BotAPIFailed(repr(ret))
    return ret['result']


def getupdates():
    global STATE
    while 1:
        try:
            updates = bot_api('getUpdates', offset=STATE['offset'], timeout=10)
        except Exception as ex:
            logger_botapi.exception('Get updates failed.')
            continue
        if updates:
            logger_botapi.debug('Messages coming.')
            STATE['offset'] = updates[-1]["update_id"] + 1
            for upd in updates:
                processmsg(upd)
        time.sleep(.2)


def processmsg(d):
    logger_botapi.debug('Msg arrived: %r' % d)
    if 'message' in d:
        msg = d['message']
        if msg['chat']['type'] == 'private' and msg.get('text', '').startswith('/t'):
            bot_api('sendMessage', chat_id=msg['chat']['id'],
                    text=CFG.url + get_token(msg['from']['id']))
            logger_botapi.info('Sent a token to %s' % msg['from'])

# Cli bot

def handle_update(obj):
    global STATE
    try:
        if obj.get('event') in ('message', 'service'):
            update_user(obj['from'])
            user_event(user, obj['date'])
        elif obj.get('event') == 'online-status':
            update_user(obj['user'])
            try:
                # it's localtime
                when = time.mktime(time.strptime(obj['when'], '%Y-%m-%d %H:%M:%S'))
                user_event(user, when)
            except ValueError:
                pass
    except Exception:
        logging.exception("can't handle message event")

# Processing

def init_db(filename):
    global DB, CONN
    DB = sqlite3.connect(filename)
    DB.row_factory = sqlite3.Row
    CONN = DB.cursor()
    CONN.execute('CREATE TABLE IF NOT EXISTS users ('
        'id INTEGER PRIMARY KEY,' # peer_id
        'username TEXT,'
        'first_name TEXT,'
        'last_name TEXT,'
        'subscribed INTEGER,'
        'timezone TEXT'
    ')')
    CONN.execute('CREATE TABLE IF NOT EXISTS events ('
        'user INTEGER,'
        'time INTEGER,'
        'PRIMARY KEY (user, time),'
        'FOREIGN KEY (user) REFERENCES users(id)'
    ')')
    CONN.execute('CREATE TABLE IF NOT EXISTS sleep ('
        'user INTEGER,'
        'time INTEGER,'
        'duration INTEGER,'
        'PRIMARY KEY (user, time),'
        'FOREIGN KEY (user) REFERENCES users(id)'
    ')')
    users = {}
    for row in CONN.execute('SELECT * FROM users'):
        users[row['id']] = dict(row)
    return users

def update_user(user, subscribed=None, timezone=None):
    uid = user.get('peer_id') or user['id']
    if uid in USER_CACHE:
        USER_CACHE[uid].update(user)
        updkey = ''
        updval = [user.get('username'), user.get('first_name', ''), user.get('last_name')]
        if subscribed is not None:
            updkey += ', subscribed=?'
            updval.append(subscribed)
        if timezone:
            updkey += ', timezone=?'
            updval.append(timezone)
        updval.append(uid)
        CONN.execute('UPDATE users SET username=?, first_name=?, last_name=?%s WHERE id=?' % updkey, updval)
    else:
        USER_CACHE[uid] = user
        timezone = USER_CACHE[uid]['timezone'] = timezone or CFG['defaulttz']
        subscribed = USER_CACHE[uid]['subscribed'] = subscribed or 0
        CONN.execute('REPLACE INTO users VALUES (?,?,?,?,?,)',
                     (uid, user.get('username'), user.get('first_name', ''),
                     user.get('last_name'), subscribed, timezone))

def user_event(user, eventtime):
    uid = user.get('peer_id') or user['id']
    CONN.execute('REPLACE INTO events (user, time) VALUES (?, ?)', (uid, eventtime))

def replace_dt_time(fromdatetime, seconds):
    return (datetime.datetime.combine(fromdatetime,
            datetime.time(tzinfo=fromdatetime.tzinfo)) +
            datetime.timedelta(seconds=seconds))

def status_update():
    '''
    Identify sleep time using rules as follows:

    -24h    0           6   now
       /=====================\  <- SELECT
       .  x-+-----------+----?
       .    |     x-----+----？
       .    |           | x--?
       .  x-+--------x x| xx
       .  x-+-----------+--x
       .  xx| x------x x| xx
       .    | x x-------+-x
       .  x |    x------+--x
       .  x | x       x-+----?
     x .    |           |    ?
    '''
    expires = time.time() - 86400
    stats = []
    for user, group in itertools.groupby(CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' WHERE events.time >= ? AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (expires,)),
        key=lambda x: x[0]):
        start, interval = None, None
        usertime = datetime.datetime.now(pytz.timezone(USER_CACHE[user]['timezone']))
        window = (replace_dt_time(usertime, CFG['cutwindow'][0]).timestamp(),
                  replace_dt_time(usertime, CFG['cutwindow'][1]).timestamp())
        lasttime = None
        left, right = None, None
        intervals = []
        for _, etime in group:
            if lasttime:
                intervals.append((etime - lasttime, lasttime))
                lasttime = etime
                if etime > window[1]:
                    right = etime
                    break
            elif etime < window[0]:
                left = etime
            elif left:
                intervals.append((etime - left, left))
                lasttime = etime
                if etime > window[1]:
                    right = etime
                    break
            else:
                lasttime = etime
        if intervals:
            if right:
                interval, start = max(intervals)
            else:
                start = etime
        elif lasttime:
            start = lasttime
        elif left:
            start = left
        # else: pass
        stats.append((user, start, interval))
    for user, start, interval in stats:
        CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?, ?, ?)',
                     (user, start, interval))
    CONN.execute('DELETE FROM events WHERE time < ?', (expires,))
    return stats

def load_config():
    cfg = AttrDict(json.load(open('config.json', encoding='utf-8')))
    if os.path.isfile('state.json'):
        state = AttrDict(json.load(open('state.json', encoding='utf-8')))
    else:
        state = AttrDict({'members': {}})
    return cfg, state


def save_config():
    json.dump(STATE, open('state.json', 'w'), sort_keys=True, indent=1)


def run(server_class=ThreadingHTTPServer, handler_class=HTTPHandler):
    server_address = (CFG.serverip, CFG.serverport)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    CFG, STATE = load_config()
    USER_CACHE = {}
    TGCLI = tgcli.TelegramCliInterface(CFG.tgclibin)
    TGCLI.ready.wait()
    TGCLI.on_json = handle_update
    try:
        USER_CACHE = init_db()
        token_gc()

        apithr = threading.Thread(target=getupdates)
        apithr.daemon = True
        apithr.start()

        run()
    finally:
        save_config()
        TGCLI.close()
