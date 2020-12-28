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


def checkIP(ip):
    return re.match(r"^(\d{1,3}\.){3}\d{1,3}(\/(\d|[1-2][0-9]|3[0-2]))?$",ip)

def get_L2_list():
    conn = sqlite3.connect('swblockbot.db')
    c = conn.cursor()
    data = c.execute("select ip from bans").fetchall()
    for i in range(len(data)):
        data[i] = data[i][0]
    return data

def refresh_ip_list():
    global ip_list
    ip_list = {
    "L2" : get_L2_list(), # TODO Подумать над ним
    "SW" : ["1.4.8.8", "14.88.14.88"], #requests.get(creds.SW_blacklist_url, headers=headers).json['list'],
    "list" : [],
    "wrong" : [],
    "fail" : []
}

def ip_list_to_data(ip_list):
    return json.dumps({"list" : ip_list})


def restricted(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        if not is_user(update.effective_user.id):
            context.bot.send_message(chat_id=update.effective_chat.id, text="Для использования данной команды необходимо пройти процесс регистрации, отправьте /start боту в ЛС.")
            logger.info("Unauthorized access denied for id {}, name: {}.".format(update.effective_user.id, update.message.from_user.full_name))
            return
        if update.effective_chat.id != creds.L2_chat_id:
            context.bot.send_message(chat_id=update.effective_chat.id, text="Команду можно использовать только в чате L2-SW Block API Bot")
            logger.info("Unauthorized access denied for id {}, name: {}, chat_id: {}".format(update.effective_user.id, update.message.from_user.full_name, update.effective_chat.id))
            return
        refresh_ip_list()
        return func(update, context, *args, **kwargs)
    return wrapped

headers = {
    'Content-Type': 'application/json',
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
    context.bot.send_message(chat_id=update.effective_chat.id, text=creds.help_text)
    logger.info("Help issued for id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))

def start(update, context):
    user_id = update.effective_user.id
    contact_keyboard = KeyboardButton(text="Зарегистрироваться", request_contact=True)
    reply_keyboard = [[contact_keyboard]]
    if not is_user(user_id):
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

def decline_auth(update, context):
    logger.info("Auth declined by id {}".format(update.effective_user.id))
    context.bot.send_message(user_id, text="Заявка отклонена, свяжитесь с @artkls для выяснения причин.")

def error(bot, update, error):
    logger.warn('Update "%s" caused error "%s"' % (update.message.from_user.text, error))

def blacklist(block, ip_list):
        #block
    if block:
        data = ip_list_to_data(ip_list)
        print('block request data: {}'.format(data))
        error_list = []
        error_list = { "error_list": [{ "type": "SSL", "code": "INVALID_CERT_KEY_PAIR" }] } #TODO
        return error_list["error_list"]
    #unblock
    data = ip_list_to_data(ip_list)
    print('unblock request data: {}'.format(data))
    error_list = []
    error_list = { "error_list": [{ "type": "SSL", "code": "INVALID_CERT_KEY_PAIR" }] } #TODO
    return error_list["error_list"]


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
    output_list.extend(set(input_list) & set(ip_list['L2'])) #TODO подумать над ним
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
    data = c.execute("SELECT IP, \
 strftime('%d.%m.', BAN_DATE) || substr(strftime('%Y', BAN_DATE),3, 2) || strftime(' %H:%M', BAN_DATE), \
  strftime('%d.%m.', UNBAN_DATE) || substr(strftime('%Y', UNBAN_DATE),3, 2) || strftime(' %H:%M', BAN_DATE), \
   BANNED_FOREVER, \
    BANNED_BY FROM BANS \
        ORDER BY UNBAN_DATE ASC").fetchall()
    list_to_show = []
    list_headers=['IP or CIDR', 'FROM', 'UNTIL', 'Banned by']
    for ip, ban_date, unban_date, banned_forever, name in data:
        banned_forever = bool(int(banned_forever))
        unban_date = 'Forever' if banned_forever else unban_date
        if context.args and len(context.args) == 1 and context.args[0] in available_args:
            #with args
            if context.args[0].lower() == 'all':
                list_to_show.append([ip, ban_date, unban_date, name])
            if context.args[0].lower() == 'forever':
                if banned_forever:
                    list_to_show.append([ip, ban_date, unban_date, name])
            if context.args[0].lower() in ['sw', 'raw']:
                #list_to_show = requests.get(creds.SW_blacklist_url, headers=headers).json #TODO
                list_to_show = {"list" : ["1.4.8.8", "14.88.14.88", "228.228.228.228", "22.8.22.8"]}
                list_headers=['IP or CIDR(Data form StormWall list, contains all blocked ips, not only from L2)']
        elif not context.args:
            #timed
            if not banned_forever:
                list_to_show.append([ip, ban_date, unban_date, name])
        else:
            #bad
            updater.bot.send_message(update.effective_chat.id, 'Некорректный аргумент {}, введите команду без аргументов для того чтобы получить список банов по времени, либо используйте допустимые аргументы: all, forever, raw'.format(' '.join(context.args)))
            return
    if not list_to_show:
        updater.bot.send_message(update.effective_chat.id, 'Данный список пуст.')
        return
    output = tabulate(list_to_show, headers=list_headers)
    if len(list_to_show) > message_lenght:
        send_filename = "{}blocklist_{}.txt".format(creds.tmp_path, datetime.datetime.now().strftime("%d%m%y_%H%M%S"))
        with open(send_filename, 'w') as out_file:
            out_file.write(output.strip("\n"))
        context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
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
            updater.bot.send_message(creds.L2_chat_id, 'Разблокированы по истечении времени бана:\n{}'.format('\n'.join(unban_list)))
            logger.info()

bot_check_active = True         

def grep_ip(update, context):
    if not context.args or len(context.args) != 1 or not checkIP(context.args[0]):
        updater.bot.send_message(update.effective_chat.id, 'Необходимо ввести один ip адрес.')
        return
    ip = context.args[0]
    subprocess.call(['sh', '/home/klassen/SWBlockBot/grep_ip_from_last_10_minutes.sh', ip])
    send_filename = "{}{}.txt".format(creds.ip_files_path, ip)
    context.bot.send_document(chat_id=update.effective_chat.id, document=open(send_filename, 'rb'))
    subprocess.call(['rm', send_filename])


def find_bots(context):
    if bot_check_active:
        list_to_show = []
        subprocess.call(['rm', '/app/jet/scripts/klassen/psaccesslog.txt'])
        subprocess.call(['sh', '/home/klassen/SWBlockBot/get_access_log_for_10min.sh'])


        with open(r'/app/jet/scripts/klassen/psaccesslog.txt') as f:
            content = f.readlines()

        ip_rt = defaultdict(list)
        for line in content:
            ip = line.split(' ', 1)[0]
            rt = re.findall(r"rt=\d\.\d{3}", line)
            if rt:
                rt = rt[0]
            if not isinstance(rt, list):
                rt = float(rt.split('=')[1])
                ip_rt[ip].append(int(rt*1000))

        list_headers=['IP', 'COUNT', 'AvgRT']
        for ip in sorted(ip_rt, key=lambda ip: len(ip_rt[ip]), reverse=True):
            if ip[:3] != '10.' and (len(ip_rt[ip]) > 600 or sum(ip_rt[ip])/len(ip_rt[ip]) > 10000):
                print("{}\t{}\t{}".format(ip, len(ip_rt[ip]), sum(ip_rt[ip])/len(ip_rt[ip])))
                list_to_show.append([ip, len(ip_rt[ip]), sum(ip_rt[ip])/len(ip_rt[ip])])
        output = tabulate(list_to_show, headers=list_headers)
        updater.bot.send_message(creds.L2_chat_id, '```\n{}```'.format(output), parse_mode=ParseMode.MARKDOWN)


def whois(update, context):
    if len(context.args) != 1: 
        updater.bot.send_message(update.effective_chat.id, 'Необходимо ввести один аргумент: IP или CIDR')
        return
    ip = context.args[0]
    data = requests.get('http://ipwhois.app/json/{}?objects=ip,success,country_code,region,city,latitude,longitude,org,isp&lang=ru'.format(ip)).json()
    if data['success']:
        output = '''IP: {} {}
REGION: {}, CITY: {}
ORG: {}
ISP: {}'''.format(data['ip'], flag.flag(data['country_code']),
        data['region'], data['city'],
        data['org'],
        data['isp'])
        logger.info("{} whois requested by id {}, name: {}".format(ip, update.effective_user.id, update.message.from_user.full_name))
        updater.bot.send_message(update.effective_chat.id, output)
        #updater.bot.send_location(latitude=data['latitude'], longitude=data['longitude'], chat_id=update.effective_chat.id)
        
@restricted
def check(update, context):
    global check_active
    if not context.args or len(context.args) != 1 or context.args[0] not in ['on', 'off']:
        updater.bot.send_message(update.effective_chat.id, 'Допустимые аргументы on и off')
        return
    if context.args[0] == 'off':
        check_active = False
        logger.info("Ban check disabled by id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))
        updater.bot.send_message(update.effective_chat.id, 'Автоматическое удаление из блок-листа по истечению времени блокировки отключено.')
    elif context.args[0] == 'on':
        check_active = True 
        logger.info("Ban check enabled by id {}, name: {}".format(update.effective_user.id, update.message.from_user.full_name))
        updater.bot.send_message(update.effective_chat.id, 'Автоматическое удаление отбывших срок из блок-листа включено каждые 5 минут.')



def main():
    """Start the bot."""
    # Create the Updater and pass it your bot's token.
    # Make sure to set use_context=True to use the new context based callbacks
    # Post version 12 this will no longer be necessary
    global updater
    updater = Updater(creds.bot_api, use_context=True)

    # Get the dispatcher to register handlers
    dp = updater.dispatcher
    prepareDB()
    updater.job_queue.run_repeating(checkAndUnban, interval=300, first=0)
    updater.job_queue.run_repeating(find_bots, interval=600, first=0)

    # on different commands - answer in Telegram
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("restart", restart))
    dp.add_handler(CommandHandler("ban", ban))
    dp.add_handler(CommandHandler("unban", unban))
    dp.add_handler(CommandHandler("timeban", timeban))
    dp.add_handler(CommandHandler("list", show_list))
    dp.add_handler(CommandHandler("check", check))
    dp.add_handler(CommandHandler("whois", whois))
    dp.add_handler(CommandHandler("grep", grep_ip))
    dp.add_handler(CommandHandler("msglen", msglen))
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
