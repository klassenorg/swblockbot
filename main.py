# -*- coding: utf-8 -*-

from telegram.ext import *
from telegram import *
import logging
import creds
import requests
import json
import datetime 
#import time
import re
import sqlite3
from functools import wraps
import subprocess
import flag
import threading
import os
import sys
from tabulate import tabulate
from collections import defaultdict
import help_txt
import cx_Oracle
import LogHandler
import socket
import urllib3
import zipfile

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def whois_api(ip):
    data = {}
    try:
        data = requests.get('http://ip-api.com/json/{}?fields=status,countryCode,region,city,isp,org,query'.format(ip)).json()
    except:
        data["status"] = "fail"
    if data["status"] == "fail":
        try:
            data = requests.get('http://ipwhois.app/json/{}?objects=ip,success,country_code,region,city,org,isp&lang=ru'.format(ip)).json()
        except:
            data["status"] = "fail"
        if not data["success"]:
            data["status"] = "fail"
            return data
        data["status"] = "success"
        data["countryCode"] = data["country_code"]
        data["query"] = data["ip"]
    data["org"], data["isp"] = data["isp"], data["org"]
    return data
        



def refresh_accesslogs(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        global last_refresh
        if datetime.datetime.now() - last_refresh >= datetime.timedelta(minutes=10):
            logger.info("Access log refresh started")
            msg = context.bot.send_message(chat_id=creds.L2_chat_id, text="Идёт сбор access логов, пожалуйста, ожидайте.")
            subprocess.call(['rm', creds.accesslogpath])
            subprocess.call(['sh', creds.get_access_log_path])
            logger.info("Access log refresh done")
            context.bot.delete_message(chat_id=creds.L2_chat_id, message_id=msg.message_id)
            last_refresh = datetime.datetime.now()
        return func(update, context, *args, **kwargs)
    return wrapped



def restricted(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        if not is_user(update.effective_user.id):
            context.bot.send_message(chat_id=update.effective_chat.id, text="Для использования данной команды необходимо пройти процесс регистрации, отправьте /start боту в ЛС.")
            logger.info("Unauthorized access denied for id {}, name: {}.".format(update.effective_user.id, update.message.from_user.full_name))
            return
        if update.effective_chat.id != creds.L2_chat_id:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Команду можно использовать только в чате MVideo ATG/StormWall BOT")
            logger.info("Unauthorized access denied for id {}, name: {}, chat_id: {}".format(update.effective_user.id, update.message.from_user.full_name, update.effective_chat.id))
            return
        refresh_ip_list()
        return func(update, context, *args, **kwargs)
    return wrapped

headers = {
    'Accept': 'text/html',
    'cookie': creds.SW_api_token,
}


AUTH = range(1)
ACCEPT_AUTH, DECLINE_AUTH = range(2)


def initdb():
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    return conn, c


def prepareDB():
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS BANS
            (IP text NOT NULL, BAN_DATE timestamp NOT NULL, UNBAN_DATE timestamp, BANNED_FOREVER integer NOT NULL, BANNED_BY text)''')

    c.execute('''CREATE TABLE IF NOT EXISTS USERS
                (ID INT NOT NULL, FULL_NAME TEXT NOT NULL, ADMIN INT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS WHITELIST
            (IP text NOT NULL, WL_DATE timestamp NOT NULL, WL_BY text)''')

    c.execute('''CREATE TABLE IF NOT EXISTS LEGAL_BOTS_IP
            (IP text NOT NULL)''')



logging.basicConfig(filename=creds.logdir,
                    filemode='a',
                    format='%(asctime)s *** %(levelname)s *** %(message)s',
                    datefmt='%d.%m.%y %H:%M:%S',
                    level=logging.INFO)

logger = logging.getLogger(__name__)

check_active = True

def stop_and_restart():
    """Gracefully stop the Updater and replace the current process with a new one"""
    updater.stop()
    os.execl(sys.executable, sys.executable, *sys.argv)

@restricted
def restart(update, context):
    logger.info("id {} name {} restarted bot.".format(update.effective_user.id, update.effective_user.full_name))
    context.bot.send_message(chat_id=update.effective_chat.id, text="Bot restarting")
    threading.Thread(target=stop_and_restart).start()

def auth_user(user_id, full_name):
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    logger.info("User id {}, name {} accepted".format(id, full_name))
    c.execute('''INSERT INTO USERS (ID, FULL_NAME, ADMIN) VALUES (?,?,?)''', (user_id, full_name, 0))
    conn.commit()

def is_user(user_id):
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    if c.execute('SELECT ID FROM USERS WHERE ID = ?',(user_id,)).fetchone():
        return True


def build_menu(buttons,
               n_cols,
               header_buttons=None,
               footer_buttons=None):
    menu = [buttons[i:i + n_cols] for i in range(0, len(buttons), n_cols)]
    if header_buttons:
        menu.insert(0, [header_buttons])
    if footer_buttons:
        menu.append([footer_buttons])
    return menu

def help(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text=help_txt.help_text)
    logger.info("Help issued for id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))

def start(update, context):
    user_id = update.effective_user.id
    contact_keyboard = KeyboardButton(text="Зарегистрироваться", request_contact=True)
    reply_keyboard = [[contact_keyboard]]
    if not is_user(user_id):
        if update.effective_chat.id == creds.L2_chat_id:
            updater.bot.send_message(update.effective_chat.id, "Данную команду нужно отправить боту в личные сообщения.")
            return
        updater.bot.send_message(update.effective_chat.id, "Необходимо пройти процесс регистрации, нажми кнопку 'Зарегестрироваться' чтобы предоставить свои данные.",
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True))
        logger.info("Start issued for id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))
    else:
        logger.info("Repeated attempt for register issues by id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))
        text = 'Ты уже зарегистирован, можешь использовать команды.'
        context.bot.send_message(chat_id=update.effective_chat.id, text=text)
        return ConversationHandler.END

    return AUTH


def cancel(update, context):
    logger.info("Register cancel issued for id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))
    updater.bot.send_message(update.effective_chat.id, 'Регистрация отменена.',
                              reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


def auth_request(update, context):
    global user_id, user_full_name
    user = update.message.from_user
    user_id = user.id
    user_full_name = user.full_name
    text = 'Кто-то пытается зарегистрироваться c id - ' + str(user.id) + ' и именем - ' + str(user.full_name)
    button_list = [
        InlineKeyboardButton("Отклонить", callback_data='0'),
        InlineKeyboardButton("Подтвердить", callback_data='1')
    ]
    reply_markup = InlineKeyboardMarkup(build_menu(button_list, n_cols=1))
    context.bot.send_message(635651868, text=text, reply_markup=reply_markup, remove_keyboard=True)
    updater.bot.send_message(update.effective_chat.id, 'Ожидайте подтверждения вашей учетной записи.')

def accept_auth(update, context):
    auth_user(user_id, user_full_name)
    logger.info("Auth accepted by id {}".format(update.effective_user.id))
    context.bot.send_message(user_id, text="Ваша учётная запись подтверждена, можете пользоваться ботом.")
    context.bot.send_message(635651868, text="Пользователь авторизован",remove_keyboard=True)

def decline_auth(update, context):
    logger.info("Auth declined by id {}".format(update.effective_user.id))
    context.bot.send_message(user_id, text="Заявка отклонена, свяжитесь с @artkls для выяснения причин.")

def error(bot, update, error):
    logger.warn('Update "%s" caused error "%s"' % (update.message.from_user.text, error))

def checkIP(ip):
    return re.match(r"^(\d{1,3}\.){3}\d{1,3}(\/(\d|[1-2][0-9]|3[0-2]))?$",ip)

def get_L2_list():
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    data = c.execute("select ip from bans").fetchall()
    for i in range(len(data)):
        data[i] = data[i][0]
    return data

def get_SW_list():
    raw_list = requests.get(creds.SW_blacklist_url, headers=creds.headers, verify=False).json()['list']
    output_list = []
    for ip in raw_list:
        output_list.append(ip.replace('/32', ''))
    return output_list

def refresh_ip_list():
    global ip_list
    ip_list = {
    "L2" : [],#get_L2_list(), # TODO Подумать над ним
    "SW" : get_SW_list(),
    "list" : [],
    "wrong" : [],
    "fail" : []
}

def ip_list_to_data(ip_list):
    new_list = [ip+'/32' if '/' not in ip else ip for ip in ip_list]
    return json.dumps({"list" : new_list})

def blacklist(block, ip_list):
    data = ip_list_to_data(ip_list)
        #block
    if block:
        response = requests.put('https://api.stormwall.pro/user/service/{}/domain/{}/ddos/black-cidr-list'.format(creds.SW_service_id, creds.SW_domain_id), headers=creds.headers, data=data, verify=False)
        error_list = response.json()["error_list"]
        return error_list
    #unblock
    response = requests.delete('https://api.stormwall.pro/user/service/{}/domain/{}/ddos/black-cidr-list'.format(creds.SW_service_id, creds.SW_domain_id), headers=creds.headers, data=data, verify=False)
    error_list = response.json()["error_list"]
    return error_list


def checkArgs(args):
    #check for args
    if not args:
        updater.bot.send_message(creds.L2_chat_id, 'Для использования данной команды необходимо ввести корректный(е) ip адрес(а) через пробел, например /ban 1.2.3.4 или /unban 2.3.4.5 3.4.5.6 или /timeban 4.5.6.7 5.6.7.8 6.7.8.9 10, где 10 - время в часах на которое необходимо заблокировать данный список ip')
        return
    ip_list = args
    #check for correct ip
    if not all(checkIP(ip) for ip in ip_list):
        updater.bot.send_message(creds.L2_chat_id, 'Введены некорректные аргументы, проверьте корректность ip адресов: {}'.format((' '.join([ip for ip in ip_list if not checkIP(ip)]))))
        return
    
    output = ''
    #check for duplicates
    if len(ip_list) != len(set(ip_list)):
        output += 'В запросе были обнаружены дубликаты:\n{}\nДубликаты были удалены автоматически.\n'.format(('\n'.join(set([ip for ip in ip_list if ip_list.count(ip) > 1]))))
        ip_list = list(dict.fromkeys(ip_list))
    return ip_list, output


#вычленить айпишники которые в бан листе
def get_ip_list_that_in_ban_lists(input_list):
    output_list = []
    output_list.extend(set(input_list) & set(ip_list['SW']))
    #output_list.extend(set(input_list) & set(ip_list['L2'])) #TODO подумать над ним
    output_list = list(dict.fromkeys(output_list))
    return output_list

#функции для бана/разбана
@restricted
def ban(update, context):
    ip_list['list'], output = checkArgs(context.args)
    if not ip_list['list']:
        return
    bad_list = get_ip_list_that_in_ban_lists(ip_list['list'])
    ip_list['list'] = list(filter(lambda ip: ip not in bad_list, ip_list['list']))
    if bad_list:
        output += 'Данные ip не были заблокированы, так как они уже находятся в блок-листе:\n{}\n'.format('\n'.join(bad_list))
    if ip_list['list']:
        response = blacklist(True, ip_list['list'])
        output += 'Данные ip были заблокированы:\n{}\n'.format('\n'.join(ip_list['list']))
        logger.info('id {}, {} banned {} ***'.format(update.effective_user.id, update.message.from_user.full_name, ' '.join(ip_list['list'])))
        if response:
            output += 'Данные "мягкие" ошибки произошли при оправке ip в StormWall:\n{}\n'.format('\n'.join(str(item) for item in response))
    conn, c = initdb()
    for ip in ip_list['list']:
        c.execute("INSERT INTO BANS (ip, ban_date, banned_forever, banned_by) VALUES(?,?,?,?)",(ip, datetime.datetime.now(), 1, update.message.from_user.full_name))
    updater.bot.send_message(creds.L2_chat_id, output)
    conn.commit()

@restricted
def unban(update, context):
    ip_list['list'], output = checkArgs(context.args)
    if not ip_list['list']:
        return
    good_list = get_ip_list_that_in_ban_lists(ip_list['list'])
    ip_list['list'] = list(filter(lambda ip: ip not in good_list, ip_list['list']))
    if ip_list['list']:
        output += 'Данные ip не были разблокированы, так как они не находятся в блок-листе:\n{}\n'.format('\n'.join(ip_list['list']))
    if good_list:
        response = blacklist(False, good_list)
        output += 'Данные ip были разблокированы:\n{}\n'.format('\n'.join(good_list))
        logger.info('id {}, {} banned {} ***'.format(update.effective_user.id, update.message.from_user.full_name, ' '.join(good_list)))
        if response:
            output += 'Данные "мягкие" ошибки произошли при оправке ip в StormWall:\n{}\n'.format('\n'.join(str(item) for item in response))#response.ip_list['list']))
    conn, c = initdb()
    for ip in good_list:
        c.execute("DELETE FROM BANS WHERE ip = ?", (ip,))
    updater.bot.send_message(creds.L2_chat_id, output)
    conn.commit()

@restricted
def timeban(update, context):
    ip_list['list'], output = checkArgs(context.args[:-1])
    hours = context.args[-1]
    if not ip_list['list']:
        return
    if not hours.isdigit() or checkIP(hours):
        updater.bot.send_message(creds.L2_chat_id, 'Последним аргументом необходимо ввести время в часах, на которое необходимо заблокировать адрес(a), некорректная запись: {}'.format(hours))
    banTill = datetime.datetime.now() + datetime.timedelta(hours=int(hours))
    bad_list = get_ip_list_that_in_ban_lists(ip_list['list'])
    ip_list['list'] = list(filter(lambda ip: ip not in bad_list, ip_list['list']))
    if bad_list:
        output += 'Данные ip не были заблокированы, так как они уже находятся в блок-листе:\n{}\n'.format('\n'.join(bad_list))
    if ip_list['list']:
        response = blacklist(True, ip_list['list'])
        output += 'Данные ip были заблокированы на {} ч.:\n{}\n'.format(hours, '\n'.join(ip_list['list']))
        logger.info('id {}, {} banned {} for {} hours. ***'.format(update.effective_user.id, update.message.from_user.full_name, ' '.join(ip_list['list']), hours))
        if response:
            output += 'Данные "мягкие" ошибки произошли при оправке ip в StormWall:\n{}\n'.format('\n'.join(str(item) for item in response))
    conn, c = initdb()
    for ip in ip_list['list']:
        c.execute("INSERT INTO BANS (ip, ban_date, unban_date, banned_forever, banned_by) VALUES(?,?,?,?,?)",(ip, datetime.datetime.now(), banTill, 0, update.message.from_user.full_name))
    updater.bot.send_message(creds.L2_chat_id, output)
    conn.commit()

message_lenght = 25

#настройка длины строки /list
@restricted
def msglen(update, context):
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент')
        return
    global message_lenght
    logger.info("Message lenght changed from {} to {} by id {}, name: {}".format(message_lenght, context.args[0], update.effective_user.id, update.message.from_user.full_name))
    message_lenght = int(context.args[0])
    updater.bot.send_message(update.effective_chat.id, 'Готово, максимальная длина списка теперь составляет {} строк'.format(message_lenght))

#/list
def show_list(update, context):
    available_args = ['all', 'forever', 'sw', 'raw']
    conn, c = initdb()
    list_to_show = []
    list_headers=['IP or CIDR', 'FROM', 'UNTIL', 'Banned by']
    data = c.execute("SELECT IP, \
    strftime('%d.%m.', BAN_DATE) || substr(strftime('%Y', BAN_DATE),3, 2) || strftime(' %H:%M', BAN_DATE), \
    strftime('%d.%m.', UNBAN_DATE) || substr(strftime('%Y', UNBAN_DATE),3, 2) || strftime(' %H:%M', UNBAN_DATE), \
    BANNED_FOREVER, \
    BANNED_BY FROM BANS \
        ORDER BY UNBAN_DATE ASC").fetchall()
    if context.args and len(context.args) == 1 and context.args[0] in available_args:
        #with args
        if context.args[0].lower() in ['sw', 'raw']:
            list_to_show = get_SW_list()
        else:
            for ip, ban_date, unban_date, banned_forever, name in data:
                banned_forever = bool(int(banned_forever))
                unban_date = 'Forever' if banned_forever else unban_date
                if context.args[0].lower() == 'all':
                    list_to_show.append([ip, ban_date, unban_date, name])
                elif context.args[0].lower() == 'forever':
                    if banned_forever:
                        list_to_show.append([ip, ban_date, unban_date, name])
                else:
                    #bad
                    updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент {}, введите команду без аргументов для того чтобы получить список банов по времени, либо используйте допустимые аргументы: all, forever, raw'.format(' '.join(context.args)))
                    return
    elif not context.args:
        #timed
        for ip, ban_date, unban_date, banned_forever, name in data:
            banned_forever = bool(int(banned_forever))
            if not banned_forever:
                list_to_show.append([ip, ban_date, unban_date, name])
    logger.info(list_to_show)
    if not list_to_show:
        updater.bot.send_message(update.effective_chat.id, 'Данный список пуст.')
        return
    output = tabulate(list_to_show, headers=list_headers)
    if context.args and context.args[0].lower() in ['sw', 'raw']:
        output = 'Количество заблокированных адресов: {}, лимит: 500 адресов, до лимита можно заблокировать еще {} адресов.\n'.format(len(list_to_show), 500-len(list_to_show))
        output += '\n'.join(list_to_show)
    if len(list_to_show) > message_lenght:
        send_filename = "{}blocklist_{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])
    else:
        updater.bot.send_message(update.effective_chat.id, '```\n{}```'.format(output), parse_mode=ParseMode.MARKDOWN)
    

def checkAndUnban(context):
    if check_active: 
        unban_list = []
        conn, c = initdb()
        data = c.execute("SELECT IP, UNBAN_DATE FROM BANS WHERE BANNED_FOREVER = 0").fetchall()
        for ip, date in data:
            if datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f') < datetime.datetime.now():
                unban_list.append(ip)
                c.execute("DELETE FROM BANS WHERE ip = ?", (ip,))
        if unban_list: 
            response = blacklist(False, unban_list)
            conn.commit()
            updater.bot.send_message(creds.L2_chat_id, '{}Разблокированы по истечении времени бана:\n{}'.format(response+'\n' if response else '', '\n'.join(unban_list)))
            logger.info()



@refresh_accesslogs
@run_async
def grep_ip(update, context):
    short = False
    if not context.args:
        updater.bot.send_message(update.effective_chat.id, 'Необходимо ввести данные для поиска')
        return
    else:
        if 'short' in context.args:
            context.args.remove('short')
            short = True
    ips = context.args
    if len(ips) > 3:
        zip_file_name = "{}grep_data_{}.zip".format(creds.ip_files_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        zip_object = zipfile.ZipFile(zip_file_name, 'a')
        msg = context.bot.send_message(chat_id=update.effective_chat.id, text="Файлов больше трех, идет сбор архива, ожидайте.")
    for ip in ips:
        if short:
            subprocess.call(['sh', creds.grep_path_short, ip])
        else:
            subprocess.call(['sh', creds.grep_path, ip])
        send_filename = "{}{}.txt".format(creds.ip_files_path, ip)
        if not os.stat(send_filename).st_size in [352, 396]:
            if len(ips) < 4:
                context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
            else:
                zip_object.write(send_filename, os.path.basename(send_filename))
        else: 
            updater.bot.send_message(update.effective_chat.id, 'По ip {} данных нет.'.format(ip))
        subprocess.call(['rm', send_filename])
    if len(ips) > 3:
        zip_object.close()
        context.bot.delete_message(chat_id=update.effective_chat.id, message_id=msg.message_id)
        try:
            context.bot.send_document(chat_id=update.effective_chat.id, document=open(zip_file_name, 'rb'))
        except Exception as e:
            updater.bot.send_message(update.effective_chat.id, e)
        subprocess.call(['rm', zip_file_name])


def verify_search_engine_bot(org, ip):
    org_list = ['google', 'yandex', 'microsoft', 'apple']
    host_list = ['googlebot.com', 'google.com', 'yandex.ru', 'yandex.net', 'yandex.com', 'search.msn.com', 'applebot.apple.com']
    if any(good_org in org.lower() for good_org in org_list):
        try:
            reversed_dns = socket.gethostbyaddr(ip)[0]
        except:
            return False
        if any(good_host in reversed_dns for good_host in host_list):
            ip_from_host = socket.gethostbyname(reversed_dns)
            if ip_from_host == ip:
                return True
        else:
            return False
    else:
        return False

@run_async
def get_ip_from_text(update, context):
    output = ''
    for arg in context.args:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', arg):
            output += arg + '\n'
    if output != '':
        updater.bot.send_message(update.effective_chat.id, '```\n{}```'.format(output[:-1]), parse_mode=ParseMode.MARKDOWN)
    else:
        updater.bot.send_message(update.effective_chat.id, 'В данном тексте нет ip')

find_bots_enabled = False

@restricted
def find_bots_switch(update, context):
    global find_bots_enabled
    if context.args and len(context.args) == 1 and context.args[0].lower() in ['on', 'off', 'status']:
        arg = context.args[0].lower()
        if arg == 'on':
            find_bots_enabled = True
            updater.bot.send_message(update.effective_chat.id, 'Поиск ботов активирован.')
        elif arg == 'off':
            find_bots_enabled = False
            updater.bot.send_message(update.effective_chat.id, 'Поиск ботов деактивирован.')
        else:
            if find_bots_enabled:
                updater.bot.send_message(update.effective_chat.id, 'В данный момент поиск ботов активирован.')
            else: 
                updater.bot.send_message(update.effective_chat.id, 'В данный момент поиск ботов деактивирован.')
    else:
        updater.bot.send_message(update.effective_chat.id, 'Некорректный аругмент, допустимые аргументы: on/off/status')

def find_bots(context):
    global find_bots_enabled
    if find_bots_enabled:
        global last_refresh
        if datetime.datetime.now() - last_refresh >= datetime.timedelta(minutes=10):
            logger.info("Access log refresh started")
            msg = context.bot.send_message(chat_id=creds.L2_chat_id, text="Идёт сбор access логов, пожалуйста, ожидайте.")
            subprocess.call(['rm', creds.accesslogpath])
            subprocess.call(['sh', creds.get_access_log_path])
            context.bot.delete_message(chat_id=creds.L2_chat_id, message_id=msg.message_id)
            logger.info("Access log refresh done")
            last_refresh = datetime.datetime.now()
        tabulate_list = []
        tabulate_headers = ['IP', 'COUNT', 'Avg.RT ms', 'REG', 'ORG']
        top_list = log_handler.get_top_by_requests_count(top=20)
        connection = cx_Oracle.connect(creds.db_auth[0], creds.db_auth[1], creds.db_auth[2])
        cursor = connection.cursor()
        for ip in top_list:
            count = len(top_list[ip])
            if count < 600: 
                break
            query = '''select count(1) from prod_production.mvid_sap_order mso where ip_user = '{}' and CREATION_DATETIME >= SYSDATE - 1'''.format(ip)
            result = int(cursor.execute(query).fetchone()[0])
            if result > 0:
                continue
            avg_rt = int(sum(top_list[ip])/count*1000)
            whois = whois_api(ip)
            if whois['status'] == 'success':
                region = flag.flag(whois['countryCode']) + whois['countryCode']
                org = whois['org']
                if verify_search_engine_bot(org, ip):
                    continue
            else: 
                region = '\U0001F3F4' + 'ZZ'
                org = 'Unknown'
            tabulate_list.append([ip, count, avg_rt, region, org])
        if tabulate_list:
            output = tabulate(tabulate_list, headers=tabulate_headers)
            updater.bot.send_message(creds.L2_chat_id, 'Вероятные боты(более 600 запросов за 10 минут, 0 заказов за последние 24 часа):\n```\n{}```'.format(output), parse_mode=ParseMode.MARKDOWN)


@restricted
def force_refresh(update, context):
    global last_refresh
    logger.info("Access log refresh started")
    msg = context.bot.send_message(chat_id=creds.L2_chat_id, text="Идёт сбор access логов, пожалуйста, ожидайте.")
    subprocess.call(['rm', creds.accesslogpath])
    subprocess.call(['sh', creds.get_access_log_path])
    context.bot.edit_message_text(chat_id=creds.L2_chat_id, message_id=msg.message_id, text='Обновление access логов завершено.')
    logger.info("Access log refresh done")
    last_refresh = datetime.datetime.now()

@refresh_accesslogs
def top_ip(update, context):
    if context.args and len(context.args) == 1 and context.args[0].isdigit():
        top = int(context.args[0])
    else: 
        top = 10
    tabulate_list = []
    tabulate_headers = ['IP', 'COUNT', 'Avg.RT ms', 'REG', 'ORG']
    top_list = log_handler.get_top_by_requests_count(top=top)
    for ip in top_list:
        count = len(top_list[ip])
        avg_rt = int(sum(top_list[ip])/count*1000)
        whois = whois_api(ip)
        if whois['status'] == 'success':
            region = flag.flag(whois['countryCode']) + whois['countryCode']
            org = whois['org']
            if verify_search_engine_bot(org, ip):
                continue
        else: 
            region = '\U0001F3F4' + 'ZZ'
            org = 'Unknown'
        tabulate_list.append([ip, count, avg_rt, region, org])
    output = tabulate(tabulate_list, headers=tabulate_headers)
    logger.info('top_ip\n' + output)
    if len(output) < 4000:
        updater.bot.send_message(update.effective_chat.id, 'TOP {} IP FOR LAST 10 MINUTES:\n```\n{}```'.format(top, output), parse_mode=ParseMode.MARKDOWN)
    else:
        send_filename = "{}top_ip{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])    
    
@refresh_accesslogs
def top_fakebot(update, context):
    conn, c = initdb()
    if context.args and len(context.args) == 1:
        try:
            all_bots = log_handler.get_top_by_ua(ua_re=context.args[0])
        except Exception as e:
            logger.info('top_fakebot exeption\n' + e)
            updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент, корректное использование: /top_fakebot regexp(любой кусок юзерагента, например Googlebot)')
            return
    tabulate_list = []
    tabulate_headers = ['IP', 'COUNT', 'REG', 'ORG']
    good_bots = c.execute("SELECT IP FROM LEGAL_BOTS_IP").fetchall()
    for ip in all_bots.copy(): #check for legal bots that in base already
        if '.'.join(ip.split('.')[:3]) in good_bots:
            del all_bots[ip]
            continue
    for ip in all_bots:
        whois = whois_api(ip)
        if whois['status'] == 'success':
            region = flag.flag(whois['countryCode']) + whois['countryCode']
            org = whois['org']
        else: 
            region = '\U0001F3F4' + 'ZZ'
            org = 'Unknown'
        if verify_search_engine_bot(whois['org'], ip):
            if '.'.join(ip.split('.')[:3]) not in c.execute("SELECT IP FROM LEGAL_BOTS_IP").fetchall():
                c.execute("INSERT INTO LEGAL_BOTS_IP (ip) VALUES(?)",('.'.join(ip.split('.')[:3])))
                conn.commit()
            continue
        else:
            count = len(all_bots[ip])
            tabulate_list.append([ip, count, region, org])
    output = tabulate(tabulate_list, headers=tabulate_headers)
    logger.info('top_fakebots\n' + output)
    if len(output) < 4000:
        updater.bot.send_message(update.effective_chat.id, 'TOP {} FAKE BOTS FOR LAST 10 MINUTES:\n```\n{}```'.format(len(tabulate_list), output), parse_mode=ParseMode.MARKDOWN)
    else:
        send_filename = "{}top_fakebots{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])    

@refresh_accesslogs
def top_guest_id(update, context):
    if context.args and len(context.args) == 1 and context.args[0].isdigit():
        top = int(context.args[0])
    else: 
        top = 10
    top_list = log_handler.get_top_by_cookie(cookie_re=r"MVID_GUEST_ID=\d{11}", top=top)
    output = ''
    for cookie in top_list:
        count = len(top_list[cookie])
        output += "{} {}:\n".format(cookie, count)
        for ip in list(set(top_list[cookie])):
            output += "{} ".format(ip)
        output = output[:-1]
        output += "\n"
    output = output[:-1]
    logger.info('top_guest_id\n' + output)
    if len(output) < 4000:
        updater.bot.send_message(update.effective_chat.id, 'TOP {} MVID GUEST ID FOR LAST 10 MINUTES:\n```\n{}```'.format(top, output), parse_mode=ParseMode.MARKDOWN)
    else:
        send_filename = "{}top_guest{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])


@refresh_accesslogs
def top_ps5(update, context):
    if context.args and len(context.args) == 1 and context.args[0].isdigit():
        top = int(context.args[0])
    else: 
        top = 10
    tabulate_list = []
    tabulate_headers = ['IP', 'COUNT', 'REG', 'ORG']
    top_list = log_handler.get_top_by_url(url_re=r"(40074203|40073270)", top=top)
    for ip in top_list:
        count = len(top_list[ip])
        whois = whois_api(ip)
        if whois['status'] == 'success':
            region = flag.flag(whois['countryCode']) + whois['countryCode']
            org = whois['org']
        else: 
            region = '\U0001F3F4' + 'ZZ'
            org = 'Unknown'
        tabulate_list.append([ip, count, region, org])
    output = tabulate(tabulate_list, headers=tabulate_headers)
    logger.info('top_ps5\n' + output)
    if len(output) < 4000:
        updater.bot.send_message(update.effective_chat.id, 'TOP {} PS5 FOR LAST 10 MINUTES:\n```\n{}```'.format(top, output), parse_mode=ParseMode.MARKDOWN)
    else:
        send_filename = "{}top_ps5{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])



@refresh_accesslogs
def top_auth(update, context):
    if context.args and len(context.args) == 1 and context.args[0].isdigit():
        top = int(context.args[0])
    else: 
        top = 10
    tabulate_list = []
    tabulate_headers = ['IP', 'COUNT', 'REG', 'ORG']
    top_list = log_handler.get_top_by_url(url_re=r"(\/byUserCredentials)|(VerificationActor\/getCodeForOtp)|(VerificationActor\/sendCodeForOtp)", top=top)
    for ip in top_list:
        count = len(top_list[ip])
        whois = whois_api(ip)
        if whois['status'] == 'success':
            region = flag.flag(whois['countryCode']) + whois['countryCode']
            org = whois['org']
        else: 
            region = '\U0001F3F4' + 'ZZ'
            org = 'Unknown'
        tabulate_list.append([ip, count, region, org])
    output = tabulate(tabulate_list, headers=tabulate_headers)
    logger.info('top_auth\n' + output)
    if len(output) < 4000:
        updater.bot.send_message(update.effective_chat.id, 'TOP {} AUTH(OTP AND CREDS) FOR LAST 10 MINUTES:\n```\n{}```'.format(top, output), parse_mode=ParseMode.MARKDOWN)
    else:
        send_filename = "{}top_auth{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
        subprocess.call(['rm', send_filename])

@refresh_accesslogs
def top_cookie(update, context):
    if context.args and len(context.args) == 1:
        try:
            top_list = log_handler.get_top_by_cookie(cookie_re=context.args[0], top=10)
        except:
            updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент, корректное использование: /top_cookie regexp(в формате cookie=value)')
            return
        output = ''
        for cookie in top_list:
            count = len(top_list[cookie])
            output += "{} {}:\n".format(cookie, count)
            for ip in list(set(top_list[cookie])):
                output += "{} ".format(ip)
            output = output[:-1]
            output += "\n"
        output = output[:-1]
        logger.info('top_cookie\n' + output)
        if len(output) < 4000:
            updater.bot.send_message(update.effective_chat.id, 'TOP {} {} FOR LAST 10 MINUTES:\n```\n{}```'.format(10, context.args[0].split('=', 1)[0], output), parse_mode=ParseMode.MARKDOWN)
        else:
            send_filename = "{}top_cookie{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
            with open(send_filename, 'w') as out_file:
                out_file.write(output.strip("\n"))
            context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
            subprocess.call(['rm', send_filename])
    else:
        updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент, корректное использование: /top_cookie regexp(в формате cookie=value)')
        return


@refresh_accesslogs
def top_url(update, context):
    if context.args and len(context.args) == 1:
            tabulate_list = []
            tabulate_headers = ['IP', 'COUNT', 'REG', 'ORG']
            top_list = log_handler.get_top_by_url(url_re=context.args[0], top=10)
            for ip in top_list:
                count = len(top_list[ip])
                whois = whois_api(ip)
                if whois['status'] == 'success':
                    region = flag.flag(whois['countryCode']) + whois['countryCode']
                    org = whois['org']
                else: 
                    region = '\U0001F3F4' + 'ZZ'
                    org = 'Unknown'
                tabulate_list.append([ip, count, region, org])
            output = tabulate(tabulate_list, headers=tabulate_headers)
            logger.info('top_url\n' + output)
            if len(output) < 4000:
                updater.bot.send_message(update.effective_chat.id, 'TOP {} IP CONTAINS {} IN URL FOR LAST 10 MINUTES:\n```\n{}```'.format(10, context.args[0], output), parse_mode=ParseMode.MARKDOWN)
            else:
                send_filename = "{}top_url{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
                with open(send_filename, 'w') as out_file:
                    out_file.write(output.strip("\n"))
                context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
                subprocess.call(['rm', send_filename])
    else:
        updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент, корректное использование: /top_url regexp')

@refresh_accesslogs
def top_status_code(update, context):
    if context.args and len(context.args) == 1:
            tabulate_list = []
            tabulate_headers = ['IP', 'COUNT', 'REG', 'ORG']
            top_list = log_handler.get_top_by_status_code(code_re=context.args[0], top=10)
            for ip in top_list:
                count = len(top_list[ip])
                whois = whois_api(ip)
                if whois['status'] == 'success':
                    region = flag.flag(whois['countryCode']) + whois['countryCode']
                    org = whois['org']
                else: 
                    region = '\U0001F3F4' + 'ZZ'
                    org = 'Unknown'
                tabulate_list.append([ip, count, region, org])
            output = tabulate(tabulate_list, headers=tabulate_headers)
            logger.info('top_code\n' + output)
            if len(output) < 4000:
                updater.bot.send_message(update.effective_chat.id, 'TOP {} IP CONTAINS {} IN STATUS CODE FOR LAST 10 MINUTES:\n```\n{}```'.format(10, context.args[0], output), parse_mode=ParseMode.MARKDOWN)
            else:
                send_filename = "{}top_code{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
                with open(send_filename, 'w') as out_file:
                    out_file.write(output.strip("\n"))
                context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
                subprocess.call(['rm', send_filename])
    else:
        updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент, корректное использование: /top_code regexp')


@run_async
def whois(update, context):
    if len(context.args) != 1: 
        updater.bot.send_message(update.effective_chat.id, 'Необходимо ввести один аргумент: IP или CIDR')
        return
    ip = context.args[0]
    data = whois_api(ip)
    if data['status'] == 'success':
        output = '''IP: {} {}
REGION: {}, CITY: {}
ORG: {}
ISP: {}'''.format(data['query'], flag.flag(data['countryCode']),
        data['region'], data['city'],
        data['org'],
        data['isp'])
        if verify_search_engine_bot(data['org'], ip):
            output += '\nДанный ip принадлежит верифицированному поисковому боту, пройдена проверка на reverse DNS lookup.'
        logger.info("{} whois requested by id {}, name: {}".format(ip, update.effective_user.id, update.message.from_user.full_name))
        connection = cx_Oracle.connect(creds.db_auth[0], creds.db_auth[1], creds.db_auth[2])
        cursor = connection.cursor()
        query = '''select count(1) from prod_production.mvid_sap_order mso where ip_user = '{}' and CREATION_DATETIME >= SYSDATE - 1'''.format(ip)
        result = int(cursor.execute(query).fetchone()[0])
        output += '\nЗа последние 24 часа с данного ip было совершено {} заказов.'.format(result)
        updater.bot.send_message(update.effective_chat.id, output)
        #updater.bot.send_location(latitude=data['latitude'], longitude=data['longitude'], chat_id=update.effective_chat.id)
        



def main():
    """Start the bot."""
    # Create the Updater and pass it your bot's token.
    # Make sure to set use_context=True to use the new context based callbacks
    # Post version 12 this will no longer be necessary
    global updater
    updater = Updater(creds.bot_api, use_context=True)

    global last_refresh
    last_refresh = datetime.datetime.now()
    logger.info("Access log refresh started")
    subprocess.call(['rm', creds.accesslogpath])
    subprocess.call(['sh', creds.get_access_log_path])
    logger.info("Access log refresh done")

    global log_handler
    log_handler = LogHandler.LogHandler(creds.accesslogpath)

    # Get the dispatcher to register handlers
    dp = updater.dispatcher
    prepareDB()
    updater.job_queue.run_repeating(checkAndUnban, interval=300, first=0)
    updater.job_queue.run_repeating(find_bots, interval=7200, first=0)

    # on different commands - answer in Telegram
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("restart", restart))
    dp.add_handler(CommandHandler("ban", ban))
    dp.add_handler(CommandHandler("unban", unban))
    dp.add_handler(CommandHandler("timeban", timeban))
    dp.add_handler(CommandHandler("list", show_list))
    dp.add_handler(CommandHandler("whois", whois))
    dp.add_handler(CommandHandler("grep", grep_ip))
    dp.add_handler(CommandHandler("msglen", msglen))
    dp.add_handler(CommandHandler("top_guest", top_guest_id))
    dp.add_handler(CommandHandler("top_ip", top_ip))
    dp.add_handler(CommandHandler("top_cookie", top_cookie))
    dp.add_handler(CommandHandler("top_auth", top_auth))
    dp.add_handler(CommandHandler("top_ps5", top_ps5))
    dp.add_handler(CommandHandler("top_url", top_url))
    dp.add_handler(CommandHandler("top_code", top_status_code))
    dp.add_handler(CommandHandler("top_fakebot", top_fakebot))
    dp.add_handler(CommandHandler("only_ip", get_ip_from_text))
    dp.add_handler(CommandHandler("force_refresh", force_refresh))
    dp.add_handler(CommandHandler("find_bots", find_bots_switch))
    dp.add_handler(CallbackQueryHandler(accept_auth, pattern='^1$'))
    dp.add_handler(CallbackQueryHandler(decline_auth, pattern='^0$'))
    auth_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],

        states={
            AUTH: [MessageHandler(Filters.contact, auth_request)]
        },

        fallbacks=[CommandHandler("cancel", cancel)]
    )
    

    dp.add_handler(auth_handler)

    updater.bot.send_message(creds.L2_chat_id, 'Bot started successfully')
    logger.info("Bot started")
    
    # on noncommand i.e message - echo the message on Telegram

    # Start the Bot
    updater.start_polling()

    # Run the bot until you press Ctrl-C or the process receives SIGINT,
    # SIGTERM or SIGABRT. This should be used most of the time, since
    # start_polling() is non-blocking and will stop the bot gracefully.
    updater.idle()


if __name__ == '__main__':
    main()
