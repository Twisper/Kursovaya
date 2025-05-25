import sys
import subprocess
import json
import os
import re # Для парсинга
import shlex # Для безопасного формирования команд

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QLabel, QListWidget, # Заменил QListView
    QTableWidget, QTabWidget, QCheckBox, QLineEdit, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QMessageBox, QFileDialog, QVBoxLayout, QListWidgetItem # Добавил QListWidgetItem
)
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, Qt, QThread, pyqtSignal # Добавил QThread, pyqtSignal для будущей реализации потоков

# --- Константы для имен файлов ---
RULES_FILE = "firewall_rules.json"
SETTINGS_FILE = "firewall_settings.json"

# --- Функции для работы с JSON ---
def save_json(data, filename):
    """Сохраняет данные в JSON файл."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Данные сохранены в {filename}")
        return True
    except IOError as e:
        print(f"Ошибка сохранения файла {filename}: {e}")
        QMessageBox.critical(None, "Ошибка сохранения", f"Не удалось сохранить файл {filename}:\n{e}")
        return False
    except TypeError as e:
        print(f"Ошибка сериализации данных в JSON ({filename}): {e}")
        QMessageBox.critical(None, "Ошибка сериализации", f"Не удалось преобразовать данные для сохранения в {filename}:\n{e}")
        return False

def load_json(filename, default_value=None):
    """Загружает данные из JSON файла."""
    if default_value is None:
        default_value = {} # По умолчанию пустой словарь
    try:
        if not os.path.exists(filename):
             print(f"Файл {filename} не найден. Используются значения по умолчанию.")
             return default_value

        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"Данные загружены из {filename}")
        # Простейшая проверка типа
        if default_value is not None and not isinstance(data, type(default_value)):
             print(f"Предупреждение: тип данных в {filename} ({type(data)}) не совпадает с ожидаемым ({type(default_value)}). Используются значения по умолчанию.")
             return default_value
        return data
    except json.JSONDecodeError as e:
        print(f"Ошибка декодирования JSON из файла {filename}: {e}")
        QMessageBox.warning(None, "Ошибка загрузки", f"Не удалось прочитать данные из {filename} (ошибка формата JSON). Будут использованы значения по умолчанию.")
        return default_value
    except IOError as e:
        print(f"Ошибка чтения файла {filename}: {e}")
        QMessageBox.warning(None, "Ошибка загрузки", f"Не удалось прочитать файл {filename}:\n{e}. Будут использованы значения по умолчанию.")
        return default_value

# --- Класс логики фаервола (Бэкэнд) ---
class FirewallLogic:
    def __init__(self):
        # Загружаем правила и настройки при инициализации
        self.rules = load_json(RULES_FILE, default_value=[]) # Ожидаем список правил
        self.settings = load_json(SETTINGS_FILE, default_value={ # Ожидаем словарь настроек
             # Значения по умолчанию для настроек
            "log_approved": False, "log_prohibited": True, "log_rejected": True,
            "log_tcp": True, "log_udp": True, "log_icmp": True,
            "unlogged_ips": ["127.0.0.1"], "unlogged_ports": [],
            "log_folder": "/var/log/" # Папка по умолчанию для логов iptables
        })
        self._is_enabled_cached = None # Кэшируем статус для скорости

    def _run_command(self, command_list):
        """Вспомогательный метод для выполнения команд с sudo и обработкой ошибок."""
        # ВАЖНО: Для реального приложения нужна безопасная обработка команд!
        # Здесь используется shlex для базового экранирования, но будьте осторожны.
        # Добавляем sudo в начало команды
        full_command = ['sudo'] + command_list
        print(f"Выполнение команды: {' '.join(shlex.quote(c) for c in full_command)}") # Логируем команду
        try:
            # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
            result = subprocess.run(full_command, capture_output=True, text=True, check=False, timeout=10) # check=False для ручной обработки ошибок

            if result.returncode != 0:
                error_message = f"Ошибка выполнения команды:\n{' '.join(command_list)}\n\nКод возврата: {result.returncode}\nОшибка:\n{result.stderr or 'Нет вывода stderr'}"
                print(error_message)
                QMessageBox.critical(None, "Ошибка команды", error_message)
                return None # Возвращаем None при ошибке

            print(f"Вывод команды:\n{result.stdout}") # Логируем вывод
            return result.stdout # Возвращаем stdout при успехе

        except FileNotFoundError:
            error_message = f"Ошибка: команда '{command_list[0]}' не найдена. Убедитесь, что iptables установлен и доступен в PATH."
            print(error_message)
            QMessageBox.critical(None, "Ошибка команды", error_message)
            return None
        except subprocess.TimeoutExpired:
            error_message = f"Ошибка: команда {' '.join(command_list)} выполнялась слишком долго."
            print(error_message)
            QMessageBox.critical(None, "Ошибка команды", error_message)
            return None
        except Exception as e:
            error_message = f"Неожиданная ошибка при выполнении команды {' '.join(command_list)}: {e}"
            print(error_message)
            QMessageBox.critical(None, "Неожиданная ошибка", error_message)
            return None

    def is_enabled(self):
        """Проверяет, включен ли фаервол (базовая проверка политики INPUT)."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        # Простая проверка: смотрим политику по умолчанию для INPUT
        output = self._run_command(['iptables', '-L', 'INPUT', '-n'])
        if output is None:
            return False # Ошибка выполнения команды

        # Ищем строку "policy DROP" или "policy REJECT"
        if "policy DROP" in output or "policy REJECT" in output:
            self._is_enabled_cached = True
            return True
        else:
             # Если политика ACCEPT, считаем фаервол "выключенным" в нашем смысле
            self._is_enabled_cached = False
            return False
        # Примечание: реальная проверка сложнее, т.к. могут быть разрешающие правила даже при политике DROP

    def enable_firewall(self):
        """Включает фаервол (устанавливает политики ACCEPT)."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        # ВАЖНО: Это очень упрощенное "включение". Обычно сюда входит загрузка правил.
        print("Backend: Установка политики ACCEPT (упрощенное включение)...")
        success = True
        if self._run_command(['iptables', '-P', 'INPUT', 'ACCEPT']) is None: success = False
        if self._run_command(['iptables', '-P', 'FORWARD', 'ACCEPT']) is None: success = False
        if self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT']) is None: success = False
        if success:
            # Можно добавить очистку текущих правил перед установкой ACCEPT:
            # self._run_command(['iptables', '-F', 'INPUT'])
            # self._run_command(['iptables', '-F', 'OUTPUT'])
            # self._run_command(['iptables', '-F', 'FORWARD'])
            print("Политики установлены в ACCEPT.")
            self._is_enabled_cached = False # Политика ACCEPT = "выключен"
            # TODO: Возможно, здесь нужно загружать сохраненные правила, а не просто ставить ACCEPT?
            # Зависит от того, что пользователь понимает под "включить".
            # self.apply_stored_rules() # Пример
        return success

    def disable_firewall(self):
        """Выключает фаервол (устанавливает политики DROP)."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        # ВАЖНО: Установка DROP заблокирует ВСЁ, включая ответ GUI!
        # В реальном приложении нужно сначала добавить разрешающие правила для SSH/GUI и т.д.
        # Либо под "выключить" понимать установку политики ACCEPT.
        # Сейчас реализуем установку DROP, но это опасно без разрешающих правил!
        print("Backend: Установка политики DROP (упрощенное выключение)...")
        reply = QMessageBox.warning(None, "Опасно!",
                                    "Установка политики DROP без разрешающих правил может заблокировать доступ к системе, включая этот интерфейс!\nВы уверены?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
             return False

        success = True
        if self._run_command(['iptables', '-P', 'INPUT', 'DROP']) is None: success = False
        if self._run_command(['iptables', '-P', 'FORWARD', 'DROP']) is None: success = False
        # Политика OUTPUT в DROP часто ломает систему, ставим ACCEPT или добавляем разрешающие правила
        if self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT']) is None: success = False
        if success:
            print("Политики установлены в DROP/ACCEPT.")
            self._is_enabled_cached = True # Политика DROP = "включен"
            # TODO: Здесь может быть логика сохранения текущих правил перед установкой DROP
        return success

    def parse_iptables_output(self, output):
        """Очень базовый парсер вывода 'iptables -L -n --line-numbers'."""
        rules = []
        lines = output.strip().split('\n')
        current_chain = None

        # Простые регулярки (могут быть неточными!)
        chain_re = re.compile(r"Chain (\S+) \(policy (\S+).*\)")
        rule_re = re.compile(
            r"^\s*(\d+)\s+" # num
            r"(pkts|bytes|\S+)\s+(\S+)\s+" # pkts, bytes (игнорируем) or target
            r"(\S+)\s+" # prot
            r"(\S+)\s+" # opt (игнорируем)
            r"(\S+)\s+" # in (игнорируем)
            r"(\S+)\s+" # out (игнорируем)
            r"(\S+)\s+" # source
            r"(\S+)"    # destination
            r"(.*)"     # Остальное (опции, комментарии)
        )
         # Улучшенная регулярка, пытающаяся захватить target и опции
        rule_re_better = re.compile(
            r"^\s*(\d+)\s+"  # 1: num
            r"\S+\s+\S+\s+"   # pkts, bytes (игнорируем)
            r"(\S+)\s+"      # 2: target
            r"(\S+)\s+"      # 3: prot
            r"\S+\s+"         # opt (игнорируем)
            r"\S+\s+"         # in (игнорируем)
            r"\S+\s+"         # out (игнорируем)
            r"(\S+)\s+"      # 4: source
            r"(\S+)"         # 5: destination
            r"(.*)"           # 6: options/comment
        )


        for line in lines:
            chain_match = chain_re.match(line)
            if chain_match:
                current_chain = chain_match.group(1)
                # print(f"Parsing chain: {current_chain}")
                continue

            if current_chain and current_chain in ["INPUT", "OUTPUT", "FORWARD"]: # Парсим только стандартные цепочки для упрощения
                rule_match = rule_re_better.match(line)
                if rule_match:
                    num, target, proto, source, destination, options_str = rule_match.groups()
                    # print(f"Matched rule: num={num}, target={target}, proto={proto}, src={source}, dst={destination}, opts='{options_str}'")

                    # Очень примитивное извлечение портов и комментариев
                    sport = "any"
                    dport = "any"
                    description = ""
                    options_str = options_str.strip()

                    sport_match = re.search(r"spt:(\S+)", options_str)
                    if sport_match: sport = sport_match.group(1)
                    dport_match = re.search(r"dpt:(\S+)", options_str)
                    if dport_match: dport = dport_match.group(1)
                    comment_match = re.search(r'/\*!"(.*)"\*/', options_str) # Новый формат комментариев
                    if not comment_match:
                        comment_match = re.search(r'--comment "(.*?)"', options_str) # Старый формат
                    if comment_match: description = comment_match.group(1)


                    rule_dict = {
                        "id": int(num), # Используем номер строки как ID для простоты
                        "chain": current_chain,
                        "enabled": True, # iptables не показывает выключенные правила в -L
                        "action": target,
                        "proto": proto,
                        "src": source,
                        "sport": sport,
                        "dst": destination,
                        "dport": dport,
                        "description": description
                    }
                    rules.append(rule_dict)

        return rules

    def get_rules(self):
        """Получает список правил из iptables."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print("Backend: Получение правил из iptables...")
        # Используем --line-numbers, чтобы получить номер строки для удаления/редактирования
        output_input = self._run_command(['iptables', '-L', 'INPUT', '-n', '--line-numbers', '-v'])
        output_output = self._run_command(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers', '-v'])
        output_forward = self._run_command(['iptables', '-L', 'FORWARD', '-n', '--line-numbers', '-v'])

        # Объединяем вывод и парсим
        full_output = (output_input or "") + "\n" + (output_output or "") + "\n" + (output_forward or "")
        # print(f"Raw iptables output:\n{full_output}") # Отладочный вывод
        parsed_rules = self.parse_iptables_output(full_output)
        print(f"Parsed {len(parsed_rules)} rules.")
        self.rules = parsed_rules # Обновляем кэш правил в логике
        return self.rules

    def delete_rule(self, rule_id, chain):
        """Удаляет правило по номеру строки (ID) и цепочке."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print(f"Backend: Удаление правила ID {rule_id} из цепочки {chain}...")
        if not chain or not rule_id:
             print("Ошибка: не указана цепочка или ID для удаления правила.")
             return False
        if self._run_command(['iptables', '-D', chain, str(rule_id)]) is not None:
            # Обновляем внутренний список правил после удаления
            self.rules = [rule for rule in self.rules if not (rule.get('chain') == chain and rule.get('id') == rule_id)]
            save_json(self.rules, RULES_FILE) # Сохраняем измененный список правил
            return True
        return False

    def add_edit_rule(self, rule_data):
        """Добавляет или редактирует правило."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print(f"Backend: Добавление/редактирование правила: {rule_data}")
        # TODO: Реализовать формирование команды iptables -A (add) или -R (replace)
        # на основе словаря rule_data. Это СЛОЖНО.
        # Примерная логика:
        cmd = ['iptables']
        chain = rule_data.get('chain', 'INPUT') # Цепочка по умолчанию
        rule_id_to_replace = rule_data.get('id_to_replace') # Если это редактирование

        if rule_id_to_replace:
            cmd.extend(['-R', chain, str(rule_id_to_replace)])
        else:
            cmd.extend(['-A', chain])

        if rule_data.get('proto') and rule_data['proto'] != 'any':
            cmd.extend(['-p', rule_data['proto']])
        if rule_data.get('src') and rule_data['src'] != 'any':
             # TODO: Обработка диапазонов/масок
            cmd.extend(['-s', rule_data['src']])
        if rule_data.get('sport') and rule_data['sport'] != 'any':
            cmd.extend(['--sport', rule_data['sport']])
        if rule_data.get('dst') and rule_data['dst'] != 'any':
             # TODO: Обработка диапазонов/масок
            cmd.extend(['-d', rule_data['dst']])
        if rule_data.get('dport') and rule_data['dport'] != 'any':
            cmd.extend(['--dport', rule_data['dport']])
        # ... другие опции (интерфейсы -i, -o, состояния -m conntrack --ctstate, etc.)

        action = rule_data.get('action', 'DROP') # Действие по умолчанию
        cmd.extend(['-j', action])

        # Добавление комментария
        description = rule_data.get('description')
        if description:
            cmd.extend(['-m', 'comment', '--comment', description])


        print(f"Сформированная команда (ПРИМЕР): {' '.join(cmd)}")
        # success = self._run_command(cmd) is not None
        success = True # Заглушка, пока команда не реализована полностью
        if success:
             print("Правило успешно добавлено/изменено (симуляция)")
             # TODO: После успешного выполнения нужно обновить self.rules и сохранить
             self.get_rules() # Перечитываем правила из системы (проще, чем обновлять вручную)
             save_json(self.rules, RULES_FILE)
             return True
        else:
             print("Ошибка добавления/изменения правила (симуляция)")
             return False


    def parse_conntrack_output(self, output):
        """Базовый парсер вывода /proc/net/nf_conntrack."""
        connections = []
        lines = output.strip().split('\n')
        # Пример строки: ipv4 2 tcp 6 431998 ESTABLISHED src=192.168.1.10 dst=1.1.1.1 sport=54321 dport=443 packets=10 bytes=1000 [ASSURED] src=1.1.1.1 dst=192.168.1.10 sport=443 dport=54321 packets=12 bytes=2000 [ASSURED] mark=0 use=1
        conn_re = re.compile(
            r"^\S+\s+\d+\s+" # proto_family, proto_num
            r"(\S+)\s+"      # 1: protocol name (tcp, udp, icmp)
            r"\d+\s+\d+\s+"   # L4 proto num, seconds left
            r"(\S+)\s+"      # 2: state (ESTABLISHED, SYN_SENT, etc.)
            r"src=(\S+)\s+dst=(\S+)\s+sport=(\S+)\s+dport=(\S+).*" # Basic connection details
            r"\[UNREPLIED\]?" # Optional unreplied flag
            r"\s+src=(\S+)\s+dst=(\S+)\s+sport=(\S+)\s+dport=(\S+)" # Reply details
        )


        for line in lines:
            match = conn_re.search(line)
            if match:
                proto, state, \
                src_ip, dst_ip, src_port, dst_port, \
                rpl_src_ip, rpl_dst_ip, rpl_src_port, rpl_dst_port = match.groups()

                # Отображаем "локальный" и "удаленный" с точки зрения нашего хоста
                # Ищем наш IP в src_ip или rpl_dst_ip (адрес назначения ответа)
                # Это упрощение, реальное определение локального адреса сложнее
                is_local_src = "192.168." in src_ip # Примерная проверка - ЗАМЕНИТЬ на реальное получение локальных IP
                is_local_dst_reply = "192.168." in rpl_dst_ip

                if is_local_src:
                    local_addr = f"{src_ip}:{src_port}"
                    remote_addr = f"{dst_ip}:{dst_port}"
                elif is_local_dst_reply:
                     local_addr = f"{rpl_dst_ip}:{rpl_dst_port}"
                     remote_addr = f"{rpl_src_ip}:{rpl_src_port}"
                else: # Если не можем определить, показываем как есть
                    local_addr = f"{src_ip}:{src_port}"
                    remote_addr = f"{dst_ip}:{dst_port}"


                connections.append({
                    "local": local_addr,
                    "remote": remote_addr,
                    "proto": proto.upper(),
                    "state": state
                })
        return connections

    def get_connections(self):
        """Получает список активных соединений из /proc/net/nf_conntrack."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print("Backend: Получение соединений из /proc/net/nf_conntrack...")
        try:
            with open('/proc/net/nf_conntrack', 'r') as f:
                output = f.read()
            return self.parse_conntrack_output(output)
        except FileNotFoundError:
             print("Ошибка: /proc/net/nf_conntrack не найден. Не могу получить список соединений.")
             # Попытка использовать conntrack -L (требует conntrack-tools)
             print("Попытка использовать 'conntrack -L'...")
             output_ct = self._run_command(['conntrack', '-L'])
             if output_ct:
                 # TODO: Написать парсер для вывода conntrack -L
                 print("Парсер для 'conntrack -L' не реализован.")
                 return []
             else:
                 QMessageBox.warning(None, "Ошибка", "/proc/net/nf_conntrack не найден и команда 'conntrack' не сработала.")
                 return []
        except IOError as e:
             print(f"Ошибка чтения /proc/net/nf_conntrack: {e}")
             QMessageBox.warning(None, "Ошибка", f"Ошибка чтения /proc/net/nf_conntrack: {e}")
             return []


    def terminate_connection(self, connection_data):
        """Разрывает соединение (добавляя правило DROP)."""
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print(f"Backend: Попытка разрыва соединения: {connection_data}")

        # Извлекаем данные (требуется парсинг строк типа "IP:Port")
        try:
            local_ip, local_port = connection_data['local'].split(':')
            remote_ip, remote_port = connection_data['remote'].split(':')
            proto = connection_data['proto'].lower() # Нужен нижний регистр для iptables
        except (KeyError, ValueError) as e:
             print(f"Ошибка разбора данных соединения: {e}")
             QMessageBox.critical(None, "Ошибка", "Неверный формат данных соединения.")
             return False

        # Формируем команду iptables для блокировки (вставка в начало INPUT)
        # Это упрощенный вариант, не учитывающий направление (может быть OUTPUT)
        # и не проверяющий, наш ли адрес локальный или удаленный
        cmd_in = ['iptables', '-I', 'INPUT', '1', # Вставить первым
                  '-p', proto,
                  '-s', remote_ip, '--sport', remote_port,
                  '-d', local_ip, '--dport', local_port,
                  '-m', 'conntrack', '--ctstate', 'ESTABLISHED', # Только для установленных
                  '-j', 'DROP']
        cmd_out = ['iptables', '-I', 'OUTPUT', '1', # Вставить первым
                   '-p', proto,
                   '-s', local_ip, '--sport', local_port,
                   '-d', remote_ip, '--dport', remote_port,
                   '-m', 'conntrack', '--ctstate', 'ESTABLISHED', # Только для установленных
                   '-j', 'DROP']

        # Пробуем добавить оба правила (т.к. не знаем точное направление)
        # ВАЖНО: Эти правила временные! Их нужно удалять (см. предыдущие обсуждения)
        # Здесь не реализовано автоматическое удаление!
        success_in = self._run_command(cmd_in) is not None
        success_out = self._run_command(cmd_out) is not None

        # Считаем успехом, если хотя бы одно правило добавилось (грубо)
        if success_in or success_out:
            print("Правила DROP для разрыва соединения добавлены (ТРЕБУЕТСЯ МЕХАНИЗМ УДАЛЕНИЯ!).")
            return True
        else:
             QMessageBox.critical(None, "Ошибка", "Не удалось добавить правила DROP для разрыва соединения.")
             return False

    def get_log_settings(self):
        """Возвращает текущие настройки логирования из self.settings."""
        print("Backend: Возврат настроек логирования...")
        return self.settings.copy() # Возвращаем копию

    def update_log_settings(self, new_settings):
        """Обновляет и сохраняет настройки логирования."""
        print(f"Backend: Обновление настроек логирования: {new_settings}")
        # TODO: Здесь можно добавить логику для применения настроек логирования
        # Например, добавить/удалить правила iptables с таргетом LOG
        # на основе чекбоксов log_approved, log_prohibited и т.д.
        # Это сложная задача. Пока просто сохраняем настройки.
        self.settings.update(new_settings) # Обновляем словарь настроек
        return save_json(self.settings, SETTINGS_FILE)

    def get_recent_actions(self):
         """Получает список последних действий из лог-файла фаервола."""
         # ** КРИТИЧНО: Чтение большого лог-файла блокирует GUI! Нужен QThread! **
         print("Backend: Получение последних действий из лога...")
         log_file_path = self.settings.get("log_folder", "/var/log/") + "kern.log" # Примерный путь
         # ВАЖНО: Реальный путь к логам iptables зависит от конфигурации rsyslog!
         actions = []
         try:
             # Читаем последние N строк файла (пример)
             num_lines_to_read = 20
             # Используем tail для эффективности (если доступен)
             cmd = ['sudo', 'tail', '-n', str(num_lines_to_read), log_file_path]
             output = self._run_command(cmd[1:]) # Вызываем без sudo, т.к. _run_command добавит его
             if output:
                 lines = output.strip().split('\n')
                 # TODO: Реализовать парсинг строк лога iptables (они могут иметь разный формат)
                 # и извлечение осмысленных действий.
                 # Пример очень простого добавления строк как есть:
                 actions = [line for line in lines if "iptables" in line or "kernel: [" in line] # Очень грубый фильтр
             else:
                 print(f"Не удалось прочитать лог-файл {log_file_path} через tail.")
                 # Можно попробовать прочитать файл напрямую (менее эффективно для больших файлов)
                 # if os.path.exists(log_file_path):
                 #     with open(log_file_path, 'r') as f:
                 #        lines = f.readlines()[-num_lines_to_read:]
                 #        actions = [line.strip() for line in lines if "iptables" in line]

         except Exception as e:
             print(f"Ошибка чтения лог-файла {log_file_path}: {e}")

         if not actions:
             actions = ["Логи не найдены или не содержат действий фаервола."]
         return actions


    def add_unlogged_ip(self, ip):
        """Добавляет IP в список нелоггируемых."""
        print(f"Backend: Добавление нелоггируемого IP: {ip}")
        if "unlogged_ips" not in self.settings:
            self.settings["unlogged_ips"] = []
        if ip not in self.settings["unlogged_ips"]:
            self.settings["unlogged_ips"].append(ip)
            return save_json(self.settings, SETTINGS_FILE)
        return True # Уже существует

    def add_unlogged_port(self, port):
        """Добавляет порт в список нелоггируемых."""
        print(f"Backend: Добавление нелоггируемого порта: {port}")
        port_str = str(port) # Храним порты как строки для единообразия
        if "unlogged_ports" not in self.settings:
            self.settings["unlogged_ports"] = []
        if port_str not in self.settings["unlogged_ports"]:
            self.settings["unlogged_ports"].append(port_str)
            return save_json(self.settings, SETTINGS_FILE)
        return True # Уже существует

    def remove_unlogged_ip(self, ip):
         """Удаляет IP из списка нелоггируемых."""
         print(f"Backend: Удаление нелоггируемого IP: {ip}")
         if "unlogged_ips" in self.settings and ip in self.settings["unlogged_ips"]:
             self.settings["unlogged_ips"].remove(ip)
             return save_json(self.settings, SETTINGS_FILE)
         return False # Не найден

    def remove_unlogged_port(self, port):
        """Удаляет порт из списка нелоггируемых."""
        print(f"Backend: Удаление нелоггируемого порта: {port}")
        port_str = str(port)
        if "unlogged_ports" in self.settings and port_str in self.settings["unlogged_ports"]:
            self.settings["unlogged_ports"].remove(port_str)
            return save_json(self.settings, SETTINGS_FILE)
        return False # Не найден


# --- Класс главного окна (Фронтэнд) ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # Загружаем UI из файла
        try:
            loadUi("firewall_main.ui", self)
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", f"Не найден файл firewall_main.ui в текущей директории ({os.getcwd()})")
            sys.exit(1)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка загрузки UI", f"Произошла ошибка при загрузке UI: {e}")
            sys.exit(1)

        self.setWindowTitle("Фаервол (iptables)") # Устанавливаем заголовок окна

        # Создаем экземпляр логики
        self.firewall_logic = FirewallLogic()

        # --- Настройка виджетов ---
        self.setup_widgets()

        # --- Подключение сигналов к слотам ---
        self.connect_signals()

        # --- Инициализация начального состояния ---
        self.initialize_ui_state()

    def setup_widgets(self):
        # Настройка таблицы правил
        self.listOfRules.setColumnCount(9) # Добавил столбец "Описание"
        self.listOfRules.setHorizontalHeaderLabels(
            ["№", "Вкл", "Действие", "Протокол", "Источник", "Порт ист.", "Назначение", "Порт назн.", "Описание"]
        )
        self.listOfRules.horizontalHeader().setStretchLastSection(True)
        self.listOfRules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfRules.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfRules.setSelectionMode(QAbstractItemView.SingleSelection)
        self.listOfRules.setColumnWidth(0, 35) # Номер
        self.listOfRules.setColumnWidth(1, 40) # Вкл/Выкл
        self.listOfRules.setColumnWidth(2, 80) # Действие
        self.listOfRules.setColumnWidth(3, 70) # Протокол
        self.listOfRules.setColumnWidth(4, 120) # Источник
        self.listOfRules.setColumnWidth(5, 60) # Порт ист.
        self.listOfRules.setColumnWidth(6, 120) # Назначение
        self.listOfRules.setColumnWidth(7, 60) # Порт назн.
        # Ширина Описания будет подстроена (StretchLastSection)

        # Настройка таблицы подключений
        self.listOfConnections.setColumnCount(4)
        self.listOfConnections.setHorizontalHeaderLabels(
             ["Локальный IP:Порт", "Удаленный IP:Порт", "Протокол", "Состояние"]
        )
        self.listOfConnections.horizontalHeader().setStretchLastSection(True)
        self.listOfConnections.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfConnections.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfConnections.setSelectionMode(QAbstractItemView.SingleSelection)

        # Замена QListView на QListWidget на вкладке Логи
        # Важно: имена объектов должны совпадать с теми, что в .ui файле!
        # Если в .ui файле имена listView и listView_2, нужно либо изменить .ui,
        # либо использовать QListView с моделями. Переименуем здесь для примера.
        # self.unloggedIpList = QListWidget() # Пример, если бы создавали программно
        # self.unloggedPortList = QListWidget()
        # Нужно будет найти существующие QListView и заменить их или настроить модели.
        # Пока предполагаем, что в .ui уже QListWidget с именами:
        # unloggedIpListWidget и unloggedPortListWidget
        # Если имена другие, исправь здесь и в connect_signals
        # --- Проверяем типы виджетов из UI ---
        if not isinstance(self.unloggedIPListWidget, QListWidget): # Используем имя из UI - unloggedIP
             print("Предупреждение: виджет unloggedIP не является QListWidget. Замените в UI или коде.")
        if not isinstance(self.unloggedPortListWidget, QListWidget):# Используем имя из UI - unloggedPorts
            print("Предупреждение: виджет unloggedPorts не является QListWidget. Замените в UI или коде.")


    def connect_signals(self):
        # --- Вкладка "Общее" ---
        self.stateButton.clicked.connect(self.toggle_firewall_state)
        # TODO: Сигнал для обновления последних действий (можно по таймеру)

        # --- Вкладка "Правила" ---
        self.addeditRuleButton.clicked.connect(self.open_add_edit_rule_dialog)
        self.deleteRuleButton.clicked.connect(self.delete_selected_rule)
        self.listOfRules.itemSelectionChanged.connect(self.update_rule_buttons_state)
        self.listOfRules.itemDoubleClicked.connect(self.open_add_edit_rule_dialog_for_selected)

        # --- Вкладка "Подключения" ---
        self.terminateConnectionButton.clicked.connect(self.terminate_selected_connection)
        self.listOfConnections.itemSelectionChanged.connect(self.update_connection_buttons_state)
        # TODO: Сигнал для обновления списка соединений (можно по таймеру)

        # --- Вкладка "Логи" ---
        self.approvedPackets.toggled.connect(self.save_current_log_settings) # Сохраняем при изменении
        self.prohibitedPackets.toggled.connect(self.save_current_log_settings)
        self.rejectedPackets.toggled.connect(self.save_current_log_settings)
        self.tcpPackets.toggled.connect(self.save_current_log_settings)
        self.udpPackets.toggled.connect(self.save_current_log_settings)
        self.icmpPackets.toggled.connect(self.save_current_log_settings)

        self.addIpButton.clicked.connect(self.add_unlogged_ip)
        self.addPortButton.clicked.connect(self.add_unlogged_port)
        self.chooseFolderButton.clicked.connect(self.choose_log_folder)

        # Подключаем сигналы для новых кнопок удаления
        if hasattr(self, 'removeIpButton'):
             self.removeIpButton.clicked.connect(self.remove_selected_unlogged_ip)
             # Выключаем кнопку по умолчанию
             self.removeIpButton.setEnabled(False)
             # Включаем кнопку при выборе элемента в списке
             if isinstance(self.unloggedIPListWidget, QListWidget):
                 self.unloggedIPListWidget.itemSelectionChanged.connect(
                     lambda: self.removeIpButton.setEnabled(len(self.unloggedIPListWidget.selectedItems()) > 0)
                 )

        if hasattr(self, 'removePortButton'):
            self.removePortButton.clicked.connect(self.remove_selected_unlogged_port)
            # Выключаем кнопку по умолчанию
            self.removePortButton.setEnabled(False)
            # Включаем кнопку при выборе элемента в списке
            if isinstance(self.unloggedPortListWidget, QListWidget):
                 self.unloggedPortListWidget.itemSelectionChanged.connect(
                      lambda: self.removePortButton.setEnabled(len(self.unloggedPortListWidget.selectedItems()) > 0)
                 )


    def initialize_ui_state(self):
        self.update_firewall_status_ui()
        self.load_and_display_rules()
        self.load_and_display_connections()
        self.load_and_display_log_settings()
        self.load_and_display_recent_actions() # Обновляем на старте
        self.update_rule_buttons_state()
        self.update_connection_buttons_state()

    # --- Слоты ---

    @pyqtSlot()
    def toggle_firewall_state(self):
        # ** КРИТИЧНО: Нужен QThread! **
        print("Сигнал: toggle_firewall_state сработал")
        # Блокируем кнопку на время выполнения
        self.stateButton.setEnabled(False)
        QApplication.processEvents() # Обновляем GUI

        logic = self.firewall_logic
        if logic.is_enabled():
            if logic.disable_firewall():
                print("Фаервол выключен")
            else:
                 QMessageBox.warning(self, "Ошибка", "Не удалось выключить фаервол")
        else:
            if logic.enable_firewall():
                print("Фаервол включен")
            else:
                 QMessageBox.warning(self, "Ошибка", "Не удалось включить фаервол")
        self.update_firewall_status_ui()
        # Разблокируем кнопку после выполнения
        self.stateButton.setEnabled(True)

    def update_firewall_status_ui(self):
        """Обновляет текст кнопки и метку статуса фаервола."""
        # ** КРИТИЧНО: is_enabled() блокирует GUI! Нужен QThread или кэш! **
        # Используем кэшированный статус, если он есть, иначе запрашиваем
        # В реальном приложении статус должен обновляться из потока через сигнал
        is_currently_enabled = self.firewall_logic._is_enabled_cached
        # Запросим статус только если он неизвестен ИЛИ если операция могла его изменить
        # (Более надежно - обновлять статус через сигнал от потока после enable/disable)
        # Для простоты пока будем запрашивать, если кэша нет
        if is_currently_enabled is None:
            # Подавляем вывод сообщения об ошибке iptables здесь, т.к. оно уже было
            # Просто вернем False, если команда не сработала
            try:
                 # Создаем временный QApplication, если основной еще не создан
                 # Это нужно, если метод вызывается до app.exec_()
                 # Лучше избегать таких вызовов до полного запуска приложения
                 _ = QApplication.instance() or QApplication(sys.argv)

                 # Вызов is_enabled может показать QMessageBox, что не идеально здесь
                 # В потоках такой проблемы не будет
                 is_currently_enabled = self.firewall_logic.is_enabled()
                 print(f"Статус фаервола запрошен: {is_currently_enabled}")
            except Exception as e:
                 print(f"Ошибка при запросе статуса в update_firewall_status_ui: {e}")
                 is_currently_enabled = False # Считаем выключенным при ошибке

        status_text = ""
        status_html = "" # Используем HTML для цвета
        button_text = ""

        if is_currently_enabled:
            button_text = "Выключить"
            status_text = "Работа фаервола: Включен"
            status_html = "Работа фаервола: <font color='green'><b>Включен</b></font>" # Жирный зеленый
            print("UI Обновлен: Фаервол ВКЛ")
        else:
            button_text = "Включить"
            status_text = "Работа фаервола: Выключен"
            status_html = "Работа фаервола: <font color='red'><b>Выключен</b></font>" # Жирный красный
            print("UI Обновлен: Фаервол ВЫКЛ")

        # Устанавливаем текст кнопки
        self.stateButton.setText(button_text)

        # Устанавливаем текст метки с поддержкой HTML
        # Убедимся, что QLabel может отображать RichText (обычно по умолчанию может)
        # self.firewallWork.setTextFormat(Qt.RichText) # Обычно не требуется для простого HTML
        self.firewallWork.setText(status_html)

        # --- Важно для обрезанной надписи! ---
        # Автоматически подгоняем размер QLabel под содержимое
        self.firewallWork.adjustSize()


    def load_and_display_recent_actions(self):
         # ** КРИТИЧНО: Чтение логов блокирует GUI! Нужен QThread! **
         print("Загрузка последних действий...")
         actions = self.firewall_logic.get_recent_actions()
         # Заполнение QListWidget (заменил QListView)
         if isinstance(self.recentActionsListWidget, QListWidget): # Используем имя из UI
             self.recentActionsListWidget.clear()
             self.recentActionsListWidget.addItems(actions)
         else:
             print("Предупреждение: виджет recentActionsListWidget не найден или не QListWidget.")


    @pyqtSlot()
    def open_add_edit_rule_dialog(self, rule_data=None):
        print("Сигнал: open_add_edit_rule_dialog сработал")
        # ЗАГЛУШКА - Здесь должно открываться диалоговое окно
        # Пример имитации добавления/редактирования
        is_edit = rule_data is not None
        action = "редактирования" if is_edit else "добавления"
        reply = QMessageBox.question(self, f"Имитация {action}",
                                     f"Имитировать успешное {action} правила?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

        if reply == QMessageBox.Yes:
            if is_edit:
                # Имитируем данные для редактирования
                rule_data_to_save = {"id_to_replace": rule_data.get("id"), "chain": "INPUT", "action": "ACCEPT", "description": "Изменено!"}
            else:
                # Имитируем данные для добавления
                rule_data_to_save = {"chain": "INPUT", "proto": "udp", "dport": "12345", "action": "ACCEPT", "description": "Новое правило!"}

            # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
            if self.firewall_logic.add_edit_rule(rule_data_to_save):
                QMessageBox.information(self, "Успех", f"Правило успешно {'изменено' if is_edit else 'добавлено'} (симуляция).")
                self.load_and_display_rules() # Обновляем таблицу
            else:
                 QMessageBox.critical(self, "Ошибка", f"Не удалось {'изменить' if is_edit else 'добавить'} правило (симуляция).")

    @pyqtSlot(QTableWidgetItem)
    def open_add_edit_rule_dialog_for_selected(self, item):
         print("Сигнал: Двойной клик по строке правила")
         selected_row = item.row()
         if selected_row >= 0:
             rule_id = self.listOfRules.item(selected_row, 0).data(Qt.UserRole) # Получаем ID
             chain = self.listOfRules.item(selected_row, 0).data(Qt.UserRole + 1) # Сохраняем цепочку тоже

             if rule_id is None or chain is None:
                  QMessageBox.warning(self, "Ошибка", "Не удалось получить ID или цепочку правила из строки.")
                  return

             # Ищем полные данные правила в нашем кэше self.firewall_logic.rules
             rule_data_full = next((rule for rule in self.firewall_logic.rules if rule.get("id") == rule_id and rule.get("chain") == chain), None)

             if rule_data_full:
                 self.open_add_edit_rule_dialog(rule_data_full)
             else:
                  QMessageBox.warning(self, "Ошибка", f"Не найдены данные для правила ID {rule_id} в цепочке {chain}.")


    @pyqtSlot()
    def delete_selected_rule(self):
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print("Сигнал: delete_selected_rule сработал")
        selected_items = self.listOfRules.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано правило для удаления.")
            return

        selected_row = selected_items[0].row()
        rule_id_item = self.listOfRules.item(selected_row, 0)
        chain_item = self.listOfRules.item(selected_row, 0) # Используем ту же ячейку для хранения цепочки

        if rule_id_item and chain_item:
            rule_id = rule_id_item.data(Qt.UserRole)
            chain = chain_item.data(Qt.UserRole + 1) # Используем UserRole + 1 для цепочки

            if rule_id is None or chain is None:
                QMessageBox.critical(self, "Ошибка", "Не удалось определить ID или цепочку правила.")
                return

            reply = QMessageBox.question(self, 'Подтверждение',
                                         f"Вы уверены, что хотите удалить правило № {rule_id} из цепочки {chain}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                 # Блокируем кнопку на время выполнения
                self.deleteRuleButton.setEnabled(False)
                QApplication.processEvents()

                if self.firewall_logic.delete_rule(rule_id, chain):
                    print(f"Правило ID {rule_id} ({chain}) удалено")
                    self.load_and_display_rules() # Обновляем таблицу
                else:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить правило ID {rule_id} ({chain}).")
                # Разблокируем кнопку
                # self.deleteRuleButton.setEnabled(True) # Состояние обновится в update_rule_buttons_state
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось получить данные правила из выбранной строки.")


    @pyqtSlot()
    def update_rule_buttons_state(self):
        has_selection = len(self.listOfRules.selectedItems()) > 0
        self.deleteRuleButton.setEnabled(has_selection)

    @pyqtSlot()
    def update_connection_buttons_state(self):
        """Обновляет состояние кнопки 'Разорвать соединение'."""
        has_selection = len(self.listOfConnections.selectedItems()) > 0
        self.terminateConnectionButton.setEnabled(has_selection)
        print(f"UI: Состояние кнопки 'Разорвать соединение' обновлено: {has_selection}")


    def load_and_display_rules(self):
        # ** КРИТИЧНО: get_rules() блокирует GUI! Нужен QThread! **
        print("Загрузка и отображение правил...")
        # Блокируем виджет на время загрузки
        self.listOfRules.setEnabled(False)
        QApplication.processEvents()

        rules = self.firewall_logic.get_rules() # Получаем уже закэшированные или свежие правила
        self.listOfRules.setRowCount(0) # Очищаем таблицу перед заполнением
        self.listOfRules.setRowCount(len(rules))

        for row_index, rule in enumerate(rules):
            item_id = QTableWidgetItem(str(rule.get("id", "")))
            item_id.setData(Qt.UserRole, rule.get("id"))
            item_id.setData(Qt.UserRole + 1, rule.get("chain")) # Сохраняем цепочку

            # Чекбокс
            item_enabled_widget = QWidget()
            chk_enabled = QCheckBox()
            chk_enabled.setChecked(rule.get("enabled", False))
            chk_enabled.setProperty("rule_id", rule.get("id"))
            chk_enabled.setProperty("chain", rule.get("chain")) # Добавляем цепочку
            chk_enabled.toggled.connect(self.toggle_rule_enabled_state)
            layout = QVBoxLayout(item_enabled_widget)
            layout.addWidget(chk_enabled)
            layout.setAlignment(Qt.AlignCenter)
            layout.setContentsMargins(0,0,0,0)
            item_enabled_widget.setLayout(layout) # Избыточно, но не вредно

            item_action = QTableWidgetItem(rule.get("action", ""))
            item_proto = QTableWidgetItem(rule.get("proto", ""))
            item_src = QTableWidgetItem(rule.get("src", ""))
            item_sport = QTableWidgetItem(rule.get("sport", ""))
            item_dst = QTableWidgetItem(rule.get("dst", ""))
            item_dport = QTableWidgetItem(rule.get("dport", ""))
            item_desc = QTableWidgetItem(rule.get("description", ""))

            # Центрирование текста для некоторых колонок
            item_id.setTextAlignment(Qt.AlignCenter)
            item_action.setTextAlignment(Qt.AlignCenter)
            item_proto.setTextAlignment(Qt.AlignCenter)

            self.listOfRules.setItem(row_index, 0, item_id)
            self.listOfRules.setCellWidget(row_index, 1, item_enabled_widget)
            self.listOfRules.setItem(row_index, 2, item_action)
            self.listOfRules.setItem(row_index, 3, item_proto)
            self.listOfRules.setItem(row_index, 4, item_src)
            self.listOfRules.setItem(row_index, 5, item_sport)
            self.listOfRules.setItem(row_index, 6, item_dst)
            self.listOfRules.setItem(row_index, 7, item_dport)
            self.listOfRules.setItem(row_index, 8, item_desc)

        # Разблокируем виджет
        self.listOfRules.setEnabled(True)
        self.update_rule_buttons_state()

    @pyqtSlot(bool)
    def toggle_rule_enabled_state(self):
         # ** КРИТИЧНО: Нужен QThread! **
         sender_checkbox = self.sender()
         if sender_checkbox:
             rule_id = sender_checkbox.property("rule_id")
             chain = sender_checkbox.property("chain")
             is_enabled = sender_checkbox.isChecked()
             print(f"Сигнал: toggle_rule_enabled_state для правила ID {rule_id} ({chain}), новое состояние: {is_enabled}")
             QMessageBox.information(self, "Функционал", "Включение/выключение правил через iptables не реализовано (требует удаления и вставки правила).")
             # TODO: Реализовать логику включения/выключения правила в FirewallLogic
             # Это сложно, т.к. iptables не имеет прямого enable/disable.
             # Обычно это требует удаления (-D) и вставки (-I или -A) правила
             # с сохранением его позиции и изменением таргета (или добавлением доп. условий).
             # Пока просто меняем состояние чекбокса обратно, если что.
             sender_checkbox.setChecked(not is_enabled) # Имитация отмены действия

    @pyqtSlot()
    def terminate_selected_connection(self):
        # ** КРИТИЧНО: Этот вызов блокирует GUI! Нужен QThread! **
        print("Сигнал: terminate_selected_connection сработал")
        selected_items = self.listOfConnections.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано соединение для разрыва.")
            return

        selected_row = selected_items[0].row()
        connection_data = None  # Инициализируем переменную

        try:
            # Получаем элементы из таблицы
            item_local = self.listOfConnections.item(selected_row, 0)
            item_remote = self.listOfConnections.item(selected_row, 1)
            item_proto = self.listOfConnections.item(selected_row, 2)
            item_state = self.listOfConnections.item(selected_row, 3)

            # Проверяем, что все ячейки существуют и не пустые
            if not all([item_local, item_remote, item_proto, item_state]):
                raise ValueError("Одна или несколько ячеек для выбранного соединения пусты.")

            # Создаем словарь connection_data ПОСЛЕ всех проверок
            connection_data = {
                "local": item_local.text(),
                "remote": item_remote.text(),
                "proto": item_proto.text(),
                "state": item_state.text(),
            }

            # --- Код, использующий connection_data, теперь находится здесь, внутри try ---
            reply = QMessageBox.question(self, 'Подтверждение',
                                         f"Вы уверены, что хотите разорвать соединение:\n{connection_data['local']} <-> {connection_data['remote']}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                # Блокируем кнопку на время выполнения
                self.terminateConnectionButton.setEnabled(False)
                QApplication.processEvents()  # Даем GUI обновиться

                if self.firewall_logic.terminate_connection(connection_data):  # Используем connection_data
                    print(f"Соединение разорвано: {connection_data}")
                    self.load_and_display_connections()  # Обновляем таблицу
                else:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось разорвать соединение.")
                # Разблокируем кнопку (состояние обновится в update_connection_buttons_state)
                # self.update_connection_buttons_state() # Вызовем чуть позже, если нужно

        except (AttributeError, ValueError, KeyError) as e:  # Ловим ошибки получения данных или ключей словаря
            print(f"Ошибка получения данных соединения: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось получить данные соединения из выбранной строки: {e}")
            # Если произошла ошибка, connection_data может быть None или не определен,
            # поэтому дальнейший код в try не выполнится.
            # Просто выходим из функции.
            return
        finally:
            # Убедимся, что кнопка разблокирована в любом случае (кроме случая, когда ошибка произошла ДО ее блокировки)
            # Проверка, была ли кнопка заблокирована (немного грубо, но сработает)
            if not self.terminateConnectionButton.isEnabled():
                self.update_connection_buttons_state()  # Обновляем состояние кнопки

        # Блокируем кнопку
        self.terminateConnectionButton.setEnabled(False)
        QApplication.processEvents()

        if self.firewall_logic.terminate_connection(connection_data):
             print(f"Соединение разорвано: {connection_data}")
             self.load_and_display_connections() # Обновляем таблицу
        else:
             QMessageBox.critical(self, "Ошибка", f"Не удалось разорвать соединение.")
        # Разблокируем кнопку (состояние обновится в update_connection_buttons_state)


    def load_and_display_connections(self):
        # ** КРИТИЧНО: get_connections() блокирует GUI! Нужен QThread! **
        print("Загрузка и отображение соединений...")
        # Блокируем виджет
        self.listOfConnections.setEnabled(False)
        QApplication.processEvents()

        connections = self.firewall_logic.get_connections()
        self.listOfConnections.setRowCount(0) # Очищаем
        self.listOfConnections.setRowCount(len(connections))

        for row_index, conn in enumerate(connections):
            item_local = QTableWidgetItem(conn.get("local", ""))
            item_remote = QTableWidgetItem(conn.get("remote", ""))
            item_proto = QTableWidgetItem(conn.get("proto", ""))
            item_state = QTableWidgetItem(conn.get("state", ""))

            self.listOfConnections.setItem(row_index, 0, item_local)
            self.listOfConnections.setItem(row_index, 1, item_remote)
            self.listOfConnections.setItem(row_index, 2, item_proto)
            self.listOfConnections.setItem(row_index, 3, item_state)

        # Разблокируем виджет
        self.listOfConnections.setEnabled(True)
        self.update_connection_buttons_state()


    @pyqtSlot()
    def save_current_log_settings(self):
         # Этот слот вызывается при изменении ЛЮБОГО чекбокса настроек
         # или при добавлении/удалении IP/порта/папки
         print(f"Сигнал: сохранение настроек логирования")
         settings = {
            "log_approved": self.approvedPackets.isChecked(),
            "log_prohibited": self.prohibitedPackets.isChecked(),
            "log_rejected": self.rejectedPackets.isChecked(),
            "log_tcp": self.tcpPackets.isChecked(),
            "log_udp": self.udpPackets.isChecked(),
            "log_icmp": self.icmpPackets.isChecked(),
            "unlogged_ips": [self.unloggedIPListWidget.item(i).text() for i in range(self.unloggedIPListWidget.count())] if isinstance(self.unloggedIPListWidget, QListWidget) else [],
            "unlogged_ports": [self.unloggedPortListWidget.item(i).text() for i in range(self.unloggedPortListWidget.count())] if isinstance(self.unloggedPortListWidget, QListWidget) else [],
            "log_folder": getattr(self, '_current_log_folder', self.firewall_logic.settings.get("log_folder", "")) # Берем из переменной или из настроек
         }
         # ** КРИТИЧНО: update_log_settings() может вызывать iptables, нужен QThread! **
         if not self.firewall_logic.update_log_settings(settings):
              QMessageBox.warning(self, "Ошибка", "Не удалось сохранить настройки логирования.")
         else:
              print("Настройки логирования сохранены")

    def load_and_display_log_settings(self):
        # ** КРИТИЧНО: get_log_settings() может читать файлы, нужен QThread! **
        print("Загрузка и отображение настроек логов...")
        settings = self.firewall_logic.get_log_settings()
        self._current_log_folder = settings.get("log_folder", "") # Сохраняем путь локально

        # --- Установка чекбоксов ---
        checkbox_map = {
            "log_approved": self.approvedPackets,
            "log_prohibited": self.prohibitedPackets,
            "log_rejected": self.rejectedPackets,
            "log_tcp": self.tcpPackets,
            "log_udp": self.udpPackets,
            "log_icmp": self.icmpPackets,
        }
        for key, checkbox in checkbox_map.items():
            checkbox.blockSignals(True)
            checkbox.setChecked(settings.get(key, False))
            checkbox.blockSignals(False)

        # --- Заполнение списков QListWidget ---
        if isinstance(self.unloggedIPListWidget, QListWidget):
            self.unloggedIPListWidget.clear()
            self.unloggedIPListWidget.addItems(settings.get("unlogged_ips", []))
        if isinstance(self.unloggedPortListWidget, QListWidget):
            self.unloggedPortListWidget.clear()
            # Порты хранятся как строки в логике, отображаем как строки
            self.unloggedPortListWidget.addItems(map(str, settings.get("unlogged_ports", [])))

        # TODO: Отобразить путь к папке логов (self._current_log_folder) где-нибудь в UI
        print(f"Текущая папка логов: {self._current_log_folder}")

    @pyqtSlot()
    def add_unlogged_ip(self):
        # ** КРИТИЧНО: add_unlogged_ip() сохраняет файл, нужен QThread! **
        print("Сигнал: add_unlogged_ip сработал")

        # Добавим проверку типа для отладки, если нужно
        if not isinstance(self.lineEdit, QLineEdit):
            QMessageBox.critical(self, "Внутренняя ошибка", "Ошибка: виджет для ввода IP не найден.")
            print("ОШИБКА: self.lineEdit не является QLineEdit!")
            return

        ip_address = self.lineEdit.text().strip()  # ip_address определяется здесь
        if not ip_address:
            QMessageBox.warning(self, "Внимание", "Введите IP-адрес.")
            return

        # TODO: Добавить валидацию IP-адреса (регулярное выражение или библиотека ipaddress)
        # import ipaddress
        # try:
        #     ipaddress.ip_address(ip_address)
        # except ValueError:
        #     QMessageBox.warning(self, "Ошибка", f"Некорректный формат IP-адреса: {ip_address}")
        #     return

        if self.firewall_logic.add_unlogged_ip(ip_address):  # Используем ip_address
            print(f"Добавлен IP: {ip_address}")
            # Обновляем только список в UI, не перезагружая все настройки
            if isinstance(self.unloggedIPListWidget, QListWidget):
                # Проверяем, нет ли уже такого элемента
                items = self.unloggedIPListWidget.findItems(ip_address, Qt.MatchExactly)
                if not items:
                    self.unloggedIPListWidget.addItem(ip_address)
            self.lineEdit.clear()
        else:
            QMessageBox.warning(self, "Ошибка", f"Не удалось добавить IP-адрес {ip_address}.")
        # ... (обработка ошибок без изменений) ...

    @pyqtSlot()
    def add_unlogged_port(self):
        # ** КРИТИЧНО: add_unlogged_port() сохраняет файл, нужен QThread! **
        print("Сигнал: add_unlogged_port сработал")

        # Проверка типа виджета
        if not isinstance(self.lineEdit_2, QLineEdit):
            QMessageBox.critical(self, "Внутренняя ошибка", "Ошибка: виджет для ввода порта не найден.")
            print("ОШИБКА: self.lineEdit_2 не является QLineEdit!")
            return

        port_str = self.lineEdit_2.text().strip()
        if not port_str:
            QMessageBox.warning(self, "Внимание", "Введите номер порта.")
            return

        try:
            port = int(port_str)  # Определяем port
            if not 0 <= port <= 65535:
                raise ValueError("Порт вне допустимого диапазона (0-65535)")

            # --- Код, использующий port, теперь находится внутри try ---
            if self.firewall_logic.add_unlogged_port(port):  # Используем port (int)
                print(f"Добавлен порт: {port}")
                # Добавляем как строку в список UI
                if isinstance(self.unloggedPortListWidget, QListWidget):
                    # Проверяем, нет ли уже такого элемента
                    items = self.unloggedPortListWidget.findItems(str(port), Qt.MatchExactly)
                    if not items:
                        self.unloggedPortListWidget.addItem(str(port))
                self.lineEdit_2.clear()
            else:
                QMessageBox.warning(self, "Ошибка", f"Не удалось добавить порт {port}.")
            # --- Конец кода, использующего port ---

        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", f"Некорректный номер порта: {e}")
            return


    @pyqtSlot()
    def remove_selected_unlogged_ip(self):
        # ** КРИТИЧНО: remove_unlogged_ip() сохраняет файл, нужен QThread! **
        if not isinstance(self.unloggedIPListWidget, QListWidget): return
        selected_items = self.unloggedIPListWidget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Внимание", "Выберите IP-адрес для удаления.")
            return
        ip_to_remove = selected_items[0].text()
        if self.firewall_logic.remove_unlogged_ip(ip_to_remove):
             # Удаляем из UI
             self.unloggedIPListWidget.takeItem(self.unloggedIPListWidget.row(selected_items[0]))
             print(f"Удален IP: {ip_to_remove}")
        else:
             QMessageBox.warning(self, "Ошибка", f"Не удалось удалить IP {ip_to_remove} (возможно, его уже нет).")

    @pyqtSlot()
    def remove_selected_unlogged_port(self):
        # ** КРИТИЧНО: remove_unlogged_port() сохраняет файл, нужен QThread! **
         if not isinstance(self.unloggedPortListWidget, QListWidget): return
         selected_items = self.unloggedPortListWidget.selectedItems()
         if not selected_items:
             QMessageBox.warning(self, "Внимание", "Выберите порт для удаления.")
             return
         port_to_remove = selected_items[0].text() # Порт хранится как строка
         if self.firewall_logic.remove_unlogged_port(port_to_remove): # Передаем строку
             # Удаляем из UI
             self.unloggedPortListWidget.takeItem(self.unloggedPortListWidget.row(selected_items[0]))
             print(f"Удален порт: {port_to_remove}")
         else:
             QMessageBox.warning(self, "Ошибка", f"Не удалось удалить порт {port_to_remove} (возможно, его уже нет).")


    @pyqtSlot()
    def choose_log_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку для логов", self._current_log_folder or os.path.expanduser("~")) # Начинаем с текущей папки логов или домашней
        if folder_path:
            print(f"Выбрана папка: {folder_path}")
            self._current_log_folder = folder_path
            # TODO: Отобразить новый путь в UI
            self.save_current_log_settings() # Сохраняем новый путь

    # Переопределяем событие закрытия окна для возможного сохранения
    def closeEvent(self, event):
        print("Событие закрытия окна")
        # Здесь можно добавить диалог подтверждения выхода
        # или дополнительное сохранение данных, если нужно
        # reply = QMessageBox.question(self, 'Выход', 'Уверены, что хотите выйти?',
        #                              QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        # if reply == QMessageBox.Yes:
        #     # Можно вызвать save_rules() и save_settings() здесь на всякий случай
        #     event.accept()
        # else:
        #     event.ignore()
        event.accept() # Просто закрываем


if __name__ == '__main__':
    # 1. ПРОВЕРКА ПРАВ СУПЕРПОЛЬЗОВАТЕЛЯ (если еще не сделана)
    if os.geteuid() != 0:
         # Создаем временный QApplication ТОЛЬКО для QMessageBox
         temp_app = QApplication(sys.argv)
         QMessageBox.critical(None,"Ошибка прав",
                                       "Это приложение требует прав суперпользователя (root) для работы с iptables.\nЗапустите его с помощью 'sudo'.",
                                      QMessageBox.Ok)
         sys.exit(1)
         # temp_app будет автоматически уничтожен при выходе

    # 2. СОЗДАНИЕ ОСНОВНОГО QApplication (ДОЛЖНО БЫТЬ ПЕРВЫМ!)
    app = QApplication(sys.argv)

    # 3. ТЕПЕРЬ МОЖНО СОЗДАВАТЬ ОКНА И ВИДЖЕТЫ
    mainWindow = MainWindow()
    mainWindow.show()

    # 4. ЗАПУСК ЦИКЛА ОБРАБОТКИ СОБЫТИЙ
    sys.exit(app.exec_())