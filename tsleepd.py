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
import queue
import sqlite3
import logging
import gettext
import datetime
import requests
import operator
import functools
import itertools
import threading
import collections
import concurrent.futures

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

tg_mktime = lambda s: time.mktime(time.strptime(s, '%Y-%m-%d %H:%M:%S'))

def handle_tg_update(obj):
    try:
        if obj.get('event') in ('message', 'service'):
            #update_user(obj['from'])
            user_event(obj['from'], obj['date'])
            if 'when' in obj['from']:
                user_event(obj['from'], tg_mktime(obj['from']['when']))
        elif obj.get('event') == 'online-status':
            #update_user(obj['user'])
            try:
                # it's localtime
                user_event(obj['user'], tg_mktime(obj['when']))
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
            updates = bot_api('getUpdates', offset=CFG['offset'], timeout=10)
        except Exception:
            logger_botapi.exception('Get updates failed.')
            continue
        if updates:
            logger_botapi.debug('Messages coming.')
            CFG['offset'] = updates[-1]["update_id"] + 1
            for upd in updates:
                MSG_Q.put(upd)
        time.sleep(.2)


def parse_cmd(text: str):
    t = text.strip().replace('\xa0', ' ').split(' ', 1)
    if not t:
        return (None, None)
    cmd = t[0].rsplit('@', 1)
    if len(cmd[0]) < 2 or cmd[0][0] not in "/'":
        return (None, None)
    expr = t[1] if len(t) > 1 else ''
    return (cmd[0][1:], expr.strip())


def handle_api_update(d):
    logger_botapi.debug('Msg arrived: %r' % d)
    if 'message' in d:
        try:
            msg = d['message']
            update_user(msg['from'])
            user_event(msg['from'], msg['date'])
            cmd, expr = parse_cmd(msg.get('text', ''))
            if cmd in COMMANDS:
                logger_botapi.info('Command: /%s %s' % (cmd, expr))
                COMMANDS[cmd](expr, msg['chat']['id'], msg['message_id'], msg)
            elif msg['chat']['type'] == 'private':
                sendmsg(_('Invalid command. Send /help for help.'), msg['chat']['id'], msg['message_id'])
            else:
                update_user_group(msg['from'], msg['chat'])
        except Exception as ex:
            logger_botapi.exception('Failed to process a message.')

# Processing

def init_db():
    global DB, CONN
    DB = sqlite3.connect(CFG['database'])
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
    CONN.execute('CREATE TABLE IF NOT EXISTS user_chats ('
        'user INTEGER,'
        'chat INTEGER,'
        'PRIMARY KEY (user, chat),'
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
        CONN.execute('INSERT OR IGNORE INTO user_chats (user, chat) VALUES (?, ?)', (uid, chat['id']))

def update_user(user, subscribed=None, timezone=None):
    uid = user.get('peer_id') or user['id']
    if uid in USER_CACHE:
        USER_CACHE[uid].update(user)
        updkey = ''
        updval = [user.get('username') or None, user.get('first_name', ''),
                  user.get('last_name')]
        if subscribed is not None:
            updkey += ', subscribed=?'
            updval.append(subscribed)
            USER_CACHE[uid]['subscribed'] = subscribed
        if timezone:
            updkey += ', timezone=?'
            updval.append(timezone)
            USER_CACHE[uid]['timezone'] = timezone
        updval.append(uid)
        CONN.execute('UPDATE users SET username=?, first_name=?, last_name=?%s WHERE id=?' % updkey, updval)
    else:
        USER_CACHE[uid] = user
        timezone = USER_CACHE[uid]['timezone'] = timezone or CFG['defaulttz']
        subscribed = USER_CACHE[uid]['subscribed'] = subscribed or 0
        CONN.execute('REPLACE INTO users VALUES (?,?,?,?,?,?)',
                     (uid, user.get('username') or None, user.get('first_name', ''),
                     user.get('last_name'), subscribed, timezone))

def user_event(user, eventtime):
    uid = user.get('peer_id') or user['id']
    if uid in USER_CACHE and USER_CACHE[uid]['subscribed']:
        CONN.execute('INSERT OR IGNORE INTO events (user, time) VALUES (?, ?)', (uid, eventtime))

def hour_minutes(seconds, zpad=True):
    m = round(seconds / 60)
    h, m = divmod(m, 60)
    if zpad:
        return '%02d:%02d' % (h, m)
    else:
        return '%d:%02d' % (h, m)

def replace_dt_time(fromdatetime, seconds):
    return (datetime.datetime.combine(fromdatetime,
            datetime.time(tzinfo=fromdatetime.tzinfo)) +
            datetime.timedelta(seconds=seconds))

def midnight_delta(fromdatetime):
    fromtimestamp = fromdatetime.timestamp()
    midnight = datetime.datetime.combine(fromdatetime, 
        datetime.time(tzinfo=fromdatetime.tzinfo)).timestamp()
    delta = fromtimestamp - midnight
    if delta > 43200:
        return delta - 86400
    else:
        return delta

midnight_adjust = lambda delta: delta + 86400 if delta < 0 else delta

def user_status(uid, events):
    '''
    Identify sleep time using rules as follows:

    -24h    0           6   now
       /=====================\  <- SELECT
       .  x-+-----------+----💤?
       .    |     x-----+----💤?
       .    |           | x  🌝?
       .  x-+--------x x| xx
       .  x-+-----------+--x
       .  xx| x------x x| xx
       .    | x x-------+-x
       .  x |    x------+--x
       .  x | x       x-+----💤?
     x .    |           |    🌝?
       . x  |           |  x 🌝?
    '''
    start, interval = None, None
    usertime = datetime.datetime.now(pytz.timezone(USER_CACHE[uid]['timezone']))
    window = (replace_dt_time(usertime, CFG['cutwindow'][0]).timestamp(),
              replace_dt_time(usertime, CFG['cutwindow'][1]).timestamp())
    lasttime = None
    left, right = None, None
    intervals = []
    for _user, etime in events:
        if lasttime:
            intervals.append((etime - lasttime, lasttime))
            lasttime = etime
            if etime > window[1]:
                right = etime
                break
        elif etime > window[1]:
            if left:
                intervals.append((etime - left, left))
                lasttime = right = etime
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
            if interval > CFG['threshold']:
                # offline for too long
                start = interval = None
        else:
            start = etime
    elif lasttime:
        start = lasttime
    elif left:
        start = left
    # else: pass
    if interval is None and start and usertime.timestamp() - start > CFG['threshold']:
        # also offline for too long
        start = None
    return start, interval

def user_status_update(uid):
    expires = time.time() - 86400
    start, interval = user_status(uid, CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' WHERE events.user = ? AND events.time >= ?'
        ' AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (uid, expires)))
    if start and interval:
        CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?,?,?)',
                     (uid, start, interval))
    return start, interval

def group_status_update(chat):
    expires = time.time() - 86400
    uid = chat['id']
    stats = []
    for user, group in itertools.groupby(tuple(CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' INNER JOIN user_chats ON events.user = user_chats.user'
        ' WHERE user_chats.chat = ? AND events.time >= ?'
        ' AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (uid, expires))),
        key=operator.itemgetter(0)):
        start, interval = user_status(user, group)
        stats.append((user, start, interval))
        if start and interval:
            CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?,?,?)',
                     (user, start, interval))
    stats.sort(key=lambda x: x[2] or 0, reverse=1)
    return stats

def all_status_update():
    expires = time.time() - 86400
    stats = []
    for user, group in itertools.groupby(tuple(CONN.execute(
        'SELECT events.user, events.time FROM events'
        ' INNER JOIN users ON events.user = users.id'
        ' WHERE events.time >= ? AND users.subscribed = 1'
        ' ORDER BY events.user ASC, events.time ASC', (expires,))),
        key=operator.itemgetter(0)):
        start, interval = user_status(user, group)
        stats.append((user, start, interval))
        if start and interval:
            CONN.execute('REPLACE INTO sleep (user, time, duration) VALUES (?,?,?)',
                     (user, start, interval))
    CONN.execute('DELETE FROM events WHERE time < ?', (expires,))
    CONN.execute('DELETE FROM sleep WHERE duration > ?', (CFG['threshold'],))
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
            if 'when' in m:
                user_event(m, tg_mktime(m['when']))

@functools.lru_cache(maxsize=100)
def db_getuidbyname(username):
    if username.startswith('#'):
        try:
            return int(username[1:])
        except ValueError:
            return None
    else:
        uid = CONN.execute('SELECT id FROM users WHERE username LIKE ?', (username,)).fetchone()
        if uid:
            return uid[0]

def cmd_status(expr, chatid, replyid, msg):
    '''/status [all|@username] - List sleeping status'''
    if expr and expr[0] == '@':
        uid = db_getuidbyname(expr[1:])
        if not uid:
            sendmsg(_('User not found.'), chatid, replyid)
            return
    elif expr == 'all' and chatid < 0:
        uid = None
    else:
        uid = msg['from']['id']
        if uid not in USER_CACHE:
            sendmsg(_('Please first /subscribe.'), chatid, replyid)
            return
    if uid:
        usertz = pytz.timezone(USER_CACHE[uid]['timezone'])
        usertime = datetime.datetime.now(usertz)
        text = [_('%s: local time is %s (%s)') % (
                getufname(USER_CACHE[uid]), usertime.strftime('%H:%M'),
                USER_CACHE[uid]['timezone'])]
        if USER_CACHE[uid]['subscribed']:
            start, interval = user_status_update(uid)
            if start:
                userstart = datetime.datetime.fromtimestamp(start, usertz)
                if interval:
                    end = userstart + datetime.timedelta(seconds=interval)
                    text.append(_('Last sleep: %s, %s→%s') % (
                        hour_minutes(interval, False),
                        userstart.strftime('%H:%M'), end.strftime('%H:%M')))
                elif (uid == msg['from']['id'] and CFG['cutwindow'][0] <
                      midnight_delta(usertime) < CFG['cutwindow'][1]):
                    text.append(_('Go to sleep!'))
                else:
                    text.append('%s→💤' % userstart.strftime('%H:%M'))
            else:
                text.append(_('Not enough data.'))
        else:
            text.append(_('Not subscribed.'))
        sendmsg('\n'.join(text), chatid, replyid)
    else:
        update_group_members(msg['chat'])
        text = []
        startsum = intrvsum = 0
        validstartcount = validintervcount = 0
        for uid, start, interval in group_status_update(msg['chat']):
            if not start:
                continue
            dispname = getufname(USER_CACHE[uid])
            usertz = pytz.timezone(USER_CACHE[uid]['timezone'])
            userstart = datetime.datetime.fromtimestamp(start, usertz)
            startsum += midnight_delta(userstart)
            validstartcount += 1
            if interval:
                end = userstart + datetime.timedelta(seconds=interval)
                text.append('%s: %s, %s→%s' % (dispname,
                    hour_minutes(interval, False),
                    userstart.strftime('%H:%M'), end.strftime('%H:%M')))
                intrvsum += interval
                validintervcount += 1
            else:
                text.append('%s: %s→💤' % (dispname, userstart.strftime('%H:%M')))
        if validintervcount:
            avgstart = startsum/validstartcount
            avginterval = intrvsum/validintervcount
            text.append(_('Average: %s, %s→%s') % (
                hour_minutes(avginterval, False),
                hour_minutes(midnight_adjust(avgstart)),
                hour_minutes(midnight_adjust(avgstart + avginterval))))
        sendmsg('\n'.join(text) or _('Not enough data.'), chatid, replyid)


def user_average_sleep(usertz, iterable):
    startsum = intrvsum = 0
    count = 0
    for start, duration in iterable:
        userstart = datetime.datetime.fromtimestamp(start, usertz)
        startsum += midnight_delta(userstart)
        intrvsum += duration
        count += 1
    if count:
        avgstart = startsum/count
        avginterval = intrvsum/count
        return (avgstart, avginterval)
    else:
        return (None, None)


def group_average_sleep(uid=None, fulllist=False):
    _self_cache = group_average_sleep.cache
    _cache_ttl = 600
    if fulllist:
        stats = []
    else:
        try:
            timestamp, avgstart, avginterval = _self_cache[uid]
            if time.time() - timestamp < _cache_ttl:
                return avgstart, avginterval
        except KeyError:
            pass
    startsum = intrvsum = 0
    count = 0
    if uid:
        result = CONN.execute(
            'SELECT sleep.user, sleep.time, sleep.duration FROM sleep'
            ' INNER JOIN users ON sleep.user = users.id'
            ' INNER JOIN user_chats ON sleep.user = user_chats.user'
            ' WHERE user_chats.chat = ? AND users.subscribed = 1'
            ' ORDER BY sleep.user', (uid,))
    else:
        result = CONN.execute(
            'SELECT sleep.user, sleep.time, sleep.duration FROM sleep'
            ' INNER JOIN users ON sleep.user = users.id'
            ' WHERE users.subscribed = 1 ORDER BY sleep.user')
    for user, group in itertools.groupby(result, key=operator.itemgetter(0)):
        usertz = pytz.timezone(USER_CACHE[user]['timezone'])
        avgstart, avginterval = user_average_sleep(usertz,
            map(operator.itemgetter(1, 2), group))
        if fulllist:
            stats.append((avginterval, avgstart, getufname(USER_CACHE[user])))
        count += 1
        startsum += avgstart
        intrvsum += avginterval
    avgstart = avginterval = None
    if count:
        avgstart = startsum/count
        avginterval = intrvsum/count
    if fulllist:
        return stats, avgstart, avginterval
    else:
        _self_cache[uid] = (time.time(), avgstart, avginterval)
        return avgstart, avginterval

group_average_sleep.cache = {}

def cmd_average(expr, chatid, replyid, msg):
    '''/average - List statistics about sleep time'''
    if expr == 'all' and chatid < 0:
        uid = None
    else:
        uid = msg['from']['id']
        if uid not in USER_CACHE:
            sendmsg(_('Please first /subscribe.'), chatid, replyid)
            return
    text = []
    if uid:
        usertz = pytz.timezone(USER_CACHE[uid]['timezone'])
        avgstart, avginterval = user_average_sleep(usertz, CONN.execute(
            'SELECT time, duration FROM sleep WHERE user = ?', (uid,)))
        if avgstart is not None:
            text.append(_('Average: %s, %s→%s') % (hour_minutes(avginterval, False),
                hour_minutes(midnight_adjust(avgstart)),
                hour_minutes(midnight_adjust(avgstart + avginterval))))
        else:
            text.append(_('Not enough data.'))
        if chatid > 0:
            avgstart, avginterval = group_average_sleep(None)
            if avgstart and avginterval:
                text.append(_('Global average: %s, %s→%s') % (
                    hour_minutes(avginterval, False),
                    hour_minutes(midnight_adjust(avgstart)),
                    hour_minutes(midnight_adjust(avgstart + avginterval))))
        else:
            avgstart, avginterval = group_average_sleep(uid)
            if avgstart and avginterval:
                text.append(_('Group average: %s, %s→%s') % (
                    hour_minutes(avginterval, False),
                    hour_minutes(midnight_adjust(avgstart)),
                    hour_minutes(midnight_adjust(avgstart + avginterval))))
    else:
        update_group_members(msg['chat'])
        uid = msg['chat']['id']
        stats, avgstart, avginterval = group_average_sleep(uid, True)
        if stats:
            stats.sort(key=lambda x: (-x[0], x[1], x[2]))
            for interval, start, dispname in stats:
                text.append('%s: %s, %s→%s' % (dispname,
                    hour_minutes(interval, False),
                    hour_minutes(midnight_adjust(start)),
                    hour_minutes(midnight_adjust(start + interval))))
            text.append(_('Group average: %s, %s→%s') % (
                hour_minutes(avginterval, False),
                hour_minutes(midnight_adjust(avgstart)),
                hour_minutes(midnight_adjust(avgstart + avginterval))))
        else:
            text.append(_('Not enough data.'))
    sendmsg('\n'.join(text), chatid, replyid)


def cmd_subscribe(expr, chatid, replyid, msg):
    '''/subscribe - Add you to the watchlist'''
    update_user(msg['from'], True)
    sendmsg(_("%s, you are subscribed.") % getufname(msg['from']), chatid, replyid)


def cmd_unsubscribe(expr, chatid, replyid, msg):
    '''/unsubscribe - Remove you from the watchlist'''
    update_user(msg['from'], False)
    sendmsg(_("%s, you are unsubscribed.") % getufname(msg['from']), chatid, replyid)

def cmd_settz(expr, chatid, replyid, msg):
    '''/settz - Set your timezone'''
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
    sendmsg(_("This is Trusted Sleep Bot. It can track users' sleep habit by using Telegram online status. Send me /help for help."), chatid, replyid)

def cmd_help(expr, chatid, replyid, msg):
    '''/help - Show usage'''
    if expr:
        if expr in COMMANDS:
            h = _(COMMANDS[expr].__doc__)
            if h:
                sendmsg(h, chatid, replyid)
            else:
                sendmsg(_('Help is not available for %s') % expr, chatid, replyid)
        else:
            sendmsg(_('Command not found.'), chatid, replyid)
    else:
        sendmsg('\n'.join(_(cmd.__doc__) for cmdname, cmd in COMMANDS.items() if cmd.__doc__), chatid, replyid)

def getufname(user, maxlen=100):
    name = user['first_name'] or ''
    if user.get('last_name'):
        name += ' ' + user['last_name']
    if len(name) > maxlen:
        name = name[:maxlen] + '…'
    return name

def load_config():
    return AttrDict(json.load(open('config.json', encoding='utf-8')))

def save_config():
    json.dump(CFG, open('config.json', 'w'), sort_keys=True, indent=1)
    DB.commit()

def handle_update(obj):
    if "update_id" in obj:
        handle_api_update(obj)
    else:
        handle_tg_update(obj)

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
    gettext.install('tsleepd', os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(sys.argv[0] or 'locale'))), 'locale'), CFG['languages'])
    DB, CONN = None, None
    MSG_Q = queue.Queue()
    USER_CACHE = {}
    TGCLI = tgcli.TelegramCliInterface(CFG.tgclibin)
    TGCLI.ready.wait()
    TGCLI.on_json = MSG_Q.put
    try:
        USER_CACHE = init_db()
        all_status_update()

        apithr = threading.Thread(target=getupdates)
        apithr.daemon = True
        apithr.start()

        while 1:
            handle_update(MSG_Q.get())
    finally:
        save_config()
        TGCLI.close()
