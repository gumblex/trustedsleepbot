#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Trusted Sleep Monitor Bot

This bot monitors group members' sleep time using online status.

Threads:
* tg-cli
  * Event: set online state
* Telegram API polling
  * /status - List sleeping status
  * /average - List statistics about sleep time
  * /help - About the bot
  * /start - Describe how to use
  * /settz - Set user timezone
  * /subscribe - Add user to watchlist
  * /unsubscribe - Remove user from watchlist
* Main
  * SQLite
    * Member
      * Basic info
      * Subscribed?
      * Timezone
    * Sleep start/end events
'''


import os
import sys
import time
import json
import sqlite3
import logging
import gettext
import datetime
import requests
import functools
import itertools
import threading

import pytz
import tgcli

logging.basicConfig(stream=sys.stderr, format='%(asctime)s [%(name)s:%(levelname)s] %(message)s', level=logging.DEBUG if sys.argv[-1] == '-v' else logging.INFO)

logger_botapi = logging.getLogger('botapi')

executor = concurrent.futures.ThreadPoolExecutor(5)
HSession = requests.Session()

class AttrDict(dict):

    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

# Cli bot

def handle_update(obj):
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

def tg_get_members(chat):
    chattype = chat.get('type')
    # To ensure the id is valid
    TGCLI.cmd_dialog_list()
    if chattype == 'group':
        peername = 'chat#id%d' % (-chat['id'])
        obj = TGCLI.cmd_chat_info(peername)
        STATE.title = obj['title']
        return obj['members']
    elif chattype == 'supergroup':
        peername = 'channel#id%d' % (-chat['id'] - 1000000000000)
        members = items = TGCLI.cmd_channel_get_members(peername, 100)
        dcount = 100
        while items:
            items = TGCLI.cmd_channel_get_members(peername, 100, dcount)
            members.extend(items)
            dcount += 100
        return members
    else:
        return

# API bot

class BotAPIFailed(Exception):
    pass

def async_func(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        def func_noerr(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception:
                logger_botapi.exception('Async function failed.')
        executor.submit(func_noerr, *args, **kwargs)
    return wrapped

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

@async_func
def sendmsg(text, chat_id, reply_to_message_id=None):
    text = text.strip()
    if not text:
        logger_botapi.warning('Empty message ignored: %s, %s' % (chat_id, reply_to_message_id))
        return
    logger_botapi.info('sendMessage(%s): %s' % (len(text), text[:20]))
    if len(text) > 2000:
        text = text[:1999] + '…'
    reply_id = reply_to_message_id
    if reply_to_message_id and reply_to_message_id < 0:
        reply_id = None
    return bot_api('sendMessage', chat_id=chat_id, text=text, reply_to_message_id=reply_id)

def getupdates():
    global CFG
    while 1:
        try:
            updates = bot_api('getUpdates', offset=STATE['offset'], timeout=10)
        except Exception:
            logger_botapi.exception('Get updates failed.')
            continue
        if updates:
            logger_botapi.debug('Messages coming.')
            CFG['offset'] = updates[-1]["update_id"] + 1
            for upd in updates:
                processmsg(upd)
        time.sleep(.2)


def parse_cmd(self, text: str):
    t = text.strip().replace('\xa0', ' ').split(' ', 1)
    if not t:
        return (None, None)
    cmd = t[0].rsplit('@', 1)
    if len(cmd[0]) < 2 or cmd[0][0] not in "/'":
        return (None, None)
    if len(cmd) > 1 and cmd[-1] not in self.usernames:
        return (None, None)
    expr = t[1] if len(t) > 1 else ''
    return (cmd[0][1:], expr)


def processmsg(d):
    logger_botapi.debug('Msg arrived: %r' % d)
    if 'message' in d:
        try:
            msg = d['message']
            cmd, expr = parse_cmd(msg.get('text', ''))
            if cmd in COMMANDS:
                logger_botapi.info('Command: /%s %s' % (cmd, expr))
                COMMANDS[cmd](expr, msg['chat']['id'], msg['message_id'], msg)
            elif msg['chat']['type'] == 'private':
                sendmsg(_('Invalid command. Send /help for help.'), chatid, replyid)
            update_user_group(msg['from'], msg['chat'])
        except Exception as ex:
            logger_botapi.exception('Failed to process a message.')

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
    CONN.execute('CREATE TABLE IF NOT EXISTS user_groups ('
        'user INTEGER,'
        'group INTEGER,'
        'PRIMARY KEY (user, group),'
        'FOREIGN KEY (user) REFERENCES users(id)'
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

def update_user_group(user, chat):
    if chat['type'].endswith('group'):
        uid = user.get('peer_id') or user['id']
        CONN.execute('INSERT OR IGNORE INTO user_groups (user, group) VALUES (?, ?)', (uid, chat['id']))

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

def user_status(uid, events):
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
    start, interval = None, None
    usertime = datetime.datetime.now(pytz.timezone(USER_CACHE[uid]['timezone']))
    window = (replace_dt_time(usertime, CFG['cutwindow'][0]).timestamp(),
              replace_dt_time(usertime, CFG['cutwindow'][1]).timestamp())
    lasttime = None
    left, right = None, None
    intervals = []
    for _, etime in events:
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
    return start, interval

def user_status_update(user):
    expires = time.time() - 86400
    uid = user['id']
    start, interval = user_status(uid, CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' WHERE events.user = ? AND events.time >= ?'
        ' AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (uid, expires))):
        start, interval = user_status(user, group)
        stats.append((user, start, interval))
    if start and interval:
        CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?,?,?)',
                     (uid, start, interval))
    return start, interval

def all_status_update():
    expires = time.time() - 86400
    stats = []
    for user, group in itertools.groupby(CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' WHERE events.time >= ? AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (expires,)),
        key=lambda x: x[0]):
        start, interval = user_status(user, group)
        stats.append((user, start, interval))
    for user, start, interval in stats:
        if start and interval:
            CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?,?,?)',
                     (user, start, interval))
    CONN.execute('DELETE FROM events WHERE time < ?', (expires,))
    return stats


def update_group_members(chat):
    members = None
    try:
        members = tg_get_members(chat)
    except Exception:
        pass
    if members:
        for m in members:
            update_user_group(m, chat)


def cmd_status(expr, chatid, replyid, msg):
    if chatid > 0:
        start, interval = user_status_update(msg['from'])
        usertime = datetime.datetime.now(pytz.timezone(USER_CACHE[msg['from']['id']]['timezone']))
        if start:
            if interval:
                ...
                sendmsg(_('Your last sleep is %s long, from %s to %s.'))
            else:
                sendmsg(_('Go to sleep!'))
        else:
            sendmsg(_('You have been offline for some time.'))
    else:
        update_group_members(msg['from'])
        #return [row[0] for row in CONN.execute(
        #'SELECT user FROM user_groups WHERE group = ?', (chat['id'],))]
    sendmsg(_("%s, you are subscribed.") % getufname(msg['from']), chatid, replyid)


def cmd_subscribe(expr, chatid, replyid, msg):
    update_user(msg['from'], True)
    sendmsg(_("%s, you are subscribed.") % getufname(msg['from']), chatid, replyid)


def cmd_unsubscribe(expr, chatid, replyid, msg):
    update_user(msg['from'], False)
    sendmsg(_("%s, you are unsubscribed.") % getufname(msg['from']), chatid, replyid)

def cmd_settz(expr, chatid, replyid, msg):
    expr = expr.strip()
    if expr and expr in pytz.all_timezones:
        update_user(msg['from'], timezone=expr)
        sendmsg(_("Your timezone is %s now.") % expr, chatid, replyid)
    else:
        try:
            current = USER_CACHE[msg['from']['id']]['timezone']
        except KeyError:
            current = CFG['defaulttz']
        sendmsg(_("Invalid timezone. Your current timezone is %s.") % current, chatid, replyid)

def cmd_start(expr, chatid, replyid, msg):
    sendmsg(_("This is Trusted Sleep Bot. It can track users' sleep habit by using Telegram online status.\nSend me /help for help."), chatid, replyid)

def cmd_help(expr, chatid, replyid, msg):
    '''/help Show usage.'''
    if expr:
        if expr in COMMANDS:
            h = COMMANDS[expr].__doc__
            if h:
                sendmsg(h, chatid, replyid)
            else:
                sendmsg(_('Help is not available for %s') % expr, chatid, replyid)
        else:
            sendmsg(_('Command not found.'), chatid, replyid)
    else:
        sendmsg('\n'.join(uniq(cmd.__doc__ for cmdname, cmd in COMMANDS.items() if cmd.__doc__)), chatid, replyid)

def getufname(user, maxlen=100):
    name = user['first_name']
    if 'last_name' in user:
        name += ' ' + user['last_name']
    if len(name) > maxlen:
        name = name[:maxlen] + '…'
    return name

def load_config():
    return AttrDict(json.load(open('config.json', encoding='utf-8')))


def save_config():
    json.dump(CFG, open('config.json', 'w'), sort_keys=True, indent=1)


def run(server_class=ThreadingHTTPServer, handler_class=HTTPHandler):
    server_address = (CFG.serverip, CFG.serverport)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


# should document usage in docstrings
COMMANDS = collections.OrderedDict((
    ('status', cmd_status),
    ('average', cmd_average),
    ('settz', cmd_settz),
    ('subscribe', cmd_subscribe),
    ('unsubscribe', cmd_unsubscribe),
    ('help', cmd_help),
    ('start', cmd_start)
))

if __name__ == '__main__':
    CFG = load_config()
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