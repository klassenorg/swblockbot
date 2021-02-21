help_text = r'''
/help - вывести список доступных команд бота
/start - зарегистрироваться для доступа к командам блокировки/разблокировки
/srv - изменить список серверов для анализа
/list - вывести блок-лист, допустимые аргументы all, forever, sw или без аргументов чтобы вывести только блокировки на время от L2
/whois - показать информацию об ip, пример: /whois 1.2.3.4
/top_ip - вывести список IP отсортированных по количеству запрсов за последние 10 минут(внимание, при выполнении данной команды ip не проверяются на количество заказов, перед блокировкой всегда проверяйте, не провайдер ли это), стандартно выводит топ 10 ip, можно указать сколько строк необходимо вывести, например /top_ip 20 
/top_guest - вывести список кук MVID_GUEST_ID и ip которые встречались с этими куками отсортированных по количеству запрсов за последние 10 минут, стандартно выводит топ 10 кук, можно указать сколько строк необходимо вывести, например /top_guest 20
/top_auth - вывести список IP отсортированных по количеству запросов на авторизацию за последние 10 минут(sendCode, getCode и byUserCredentials), стандартно выводит топ 10 ip, можно указать сколько строк необходимо вывести, например /top_auth 20
/top_ps5 - вывести список IP отсортированных по количеству запросов на страницу ps5(40073270 или 40074203 в url), стандартно выводит топ 10 ip, можно указать сколько строк необходимо вывести, например /top_auth 20
/top_cookie - вывести топ 10 кук по regexp, пример использования: /top_cookie MVID_CRM_ID=\d{10}
/top_url - вывести топ 10 ip по regexp, ищет по url, пример использования /top_url (40074203|40073270) или /top_url cart
/top_code - вывести топ 10 ip по regexp, ищет по status code
/top_fakebot - вывести всех фейковых ботов по regexp(например Googlebot)
/force_refresh - обновить сбор access логов(стандартно обновляется перед использованием каждой команды которая использует этот лог если лог старше 10 минут.)
/only_ip - преобразовать текст в список ip(удобно для блокировки)
/grep - отдает файл с запросами ip за 10 минут(если использовать после ip аргумент short, то данные будут в виде ip timestamp request user-agent), пример: /grep 1.2.3.4 или /grep 1.2.3.4 short
/ban - заблокировать IP или CIDR, может принимать множество ip, пример: /ban 1.2.3.4 или /ban 1.2.3.0/24
/unban  - разблокировать IP или CIDR, может принимать множество ip, пример: /unban 1.2.3.4 или /unban 1.2.3.0/24
/timeban - заблокировать IP или CIDR на время(в часах), может принимать множество ip, последний аргумент всегда время в часах, пример: /timeban 1.2.3.4 24 или /timeban 1.2.3.0/24 12
/msglen - изменить максимальное количество строк для /list, пример: /msglen 10
/find_bots - on/off/status переключатель автоматического поиска ботов каждые 2 часа
/find_bots_orders - on/off/status переключатель проверки массового создания заказов с одного ip
/restart - перезапустить бота
'''