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
  * SQLite
    * Member
      * Basic info
      * Subscribed?
      * Timezone
    * Chat Group
    * Sleep start/end events
'''


import os
import re
import sys
import time
import json
import socket
import logging
import requests
import threading
import socketserver
import urllib.parse

import tgcli

TIMEZONE = 8 * 3600
CUTWINDOW = (0 * 3600, 6 * 3600)

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


def get_members():
    global CFG
    # To ensure the id is valid
    TGCLI.cmd_dialog_list()
    peername = '%s#id%d' % (CFG.grouptype, CFG.groupid)
    STATE.members = {}
    if CFG.grouptype == 'channel':
        items = TGCLI.cmd_channel_get_members(peername, 100)
        for item in items:
            STATE.members[str(item['peer_id'])] = item
        dcount = 100
        while items:
            items = TGCLI.cmd_channel_get_members(peername, 100, dcount)
            for item in items:
                STATE.members[str(item['peer_id'])] = item
            dcount += 100
        STATE.title = TGCLI.cmd_channel_info(peername)['title']
    else:
        obj = TGCLI.cmd_chat_info(peername)
        STATE.title = obj['title']
        items = obj['members']
        for item in items:
            STATE.members[str(item['peer_id'])] = item
    logging.info('Original title is: ' + STATE.title)


def handle_update(obj):
    global STATE
    try:
        if (obj.get('event') == 'message' and obj['to']['peer_id'] == CFG.groupid and obj['to']['peer_type'] == CFG.grouptype):
            STATE.members[str(obj['from']['peer_id'])] = obj['from']
            STATE.title = obj['to']['title']
    except Exception:
        logging.exception("can't handle message event")

# Processing


def verify_token(token):
    serializer = URLSafeTimedSerializer(CFG.secretkey, 'Orz')
    try:
        uid = serializer.loads(token, max_age=CFG.tokenexpire)
        if str(uid) not in STATE.members:
            return False
        if time.time() - STATE.tokens[str(uid)] > CFG.tokenexpire:
            return False
    except Exception:
        return False
    return uid


def cut_title(title):
    return title[len(CFG.prefix):]


def change_title(token, title):
    uid = verify_token(token)
    if uid is False:
        return 403, {'error': 'invalid token'}
    title = RE_INVALID.sub('', title).replace('\n', ' ')
    if len(CFG.prefix + title) > 255:
        return 400, {'error': 'title too long'}
    ret = TGCLI.cmd_rename_channel('%s#id%d' % (CFG.grouptype, CFG.groupid),
                                   CFG.prefix + title)
    if ret['result'] == 'SUCCESS':
        user = STATE.members[str(uid)]
        uname = user.get('username')
        if uname:
            bot_api('sendMessage', chat_id=CFG.apigroupid,
                    text='@%s 修改了群组名称。' % uname)
        else:
            uname = user.get('first_name', '')
            if 'last_name' in user:
                uname += ' ' + user['last_name']
            bot_api('sendMessage', chat_id=CFG.apigroupid,
                    text='%s 修改了群组名称。' % uname)
        del STATE.tokens[str(uid)]
        STATE.title = CFG.prefix + title
        logging.info('@%s changed title to %s' % (uname, STATE.title))
        return 200, ret
    else:
        return 406, ret


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
    TGCLI = tgcli.TelegramCliInterface(CFG.tgclibin)
    TGCLI.ready.wait()
    TGCLI.on_json = handle_update
    try:
        if not STATE.members:
            get_members()
        token_gc()

        apithr = threading.Thread(target=getupdates)
        apithr.daemon = True
        apithr.start()

        run()
    finally:
        save_config()
        TGCLI.close()
