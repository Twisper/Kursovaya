import sys
import json
import subprocess
import re # Для базового парсинга
import shlex # Для безопасного формирования команд
import os # Для проверки прав
import logging

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QLabel, QListView,
    QTableWidget, QTabWidget, QCheckBox, QLineEdit, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QMessageBox, QFileDialog, QVBoxLayout,
    QDialog, QDialogButtonBox # Добавлено для диалога
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem # Для QListView
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, Qt, QStringListModel # Добавлено для QListView

# --- Класс для диалога добавления/редактирования ---
class AddEditRuleDialog(QDialog):
    def __init__(self, parent=None, rule_data=None):
        super().__init__(parent)
        try:
            loadUi("dialog_window.ui", self)
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", "Не найден файл dialog_window.ui")
            # Не выходим из приложения, просто закрываем диалог
            # sys.exit(1) # НЕПРАВИЛЬНО ЗДЕСЬ
            self.reject() # Закрыть диалог с ошибкой
            return
        except Exception as e:
             QMessageBox.critical(self, "Ошибка загрузки UI диалога", f"Произошла ошибка: {e}")
             # sys.exit(1) # НЕПРАВИЛЬНО ЗДЕСЬ
             self.reject()
             return

        self.setWindowTitle("Добавить/Редактировать правило")
        self.rule_data = rule_data if rule_data else {} # Храним данные редактируемого правила
        self.populate_fields()

        # Стандартное соединение кнопок OK/Cancel
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

    def populate_fields(self):
        """ Заполняет поля диалога данными существующего правила (если редактирование) """
        if not self.rule_data:
            # Устанавливаем значения по умолчанию для нового правила
            self.comboBox_2.setCurrentIndex(1) # Разрешить
            self.comboBox.setCurrentIndex(1) # TCP
            self.lineEdit.setText("any")
            self.lineEdit_2.setText("any")
            self.lineEdit_3.setText("any")
            self.lineEdit_4.setText("any")
            return

        # Заполняем для редактирования
        # Действие
        action = self.rule_data.get("action", "ACCEPT").upper()
        if action == "ACCEPT":
            self.comboBox_2.setCurrentIndex(1)
        elif action == "DROP":
            self.comboBox_2.setCurrentIndex(2)
        elif action == "REJECT":
            self.comboBox_2.setCurrentIndex(3)
        else:
             self.comboBox_2.setCurrentIndex(0) # Пусто

        # Протокол
        proto = self.rule_data.get("proto", "TCP").upper()
        if proto == "TCP":
            self.comboBox.setCurrentIndex(1)
        elif proto == "UDP":
            self.comboBox.setCurrentIndex(2)
        elif proto == "ICMP":
            self.comboBox.setCurrentIndex(3)
        else:
             self.comboBox.setCurrentIndex(0) # Пусто

        self.lineEdit.setText(self.rule_data.get("src", "any"))
        self.lineEdit_2.setText(self.rule_data.get("sport", "any"))
        self.lineEdit_3.setText(self.rule_data.get("dst", "any"))
        self.lineEdit_4.setText(self.rule_data.get("dport", "any"))
        # TODO: Добавить поле для описания в dialog_window.ui и здесь

    def get_data(self):
        """ Собирает данные из полей диалога """
        action_map = {1: "ACCEPT", 2: "DROP", 3: "REJECT"}
        proto_map = {1: "TCP", 2: "UDP", 3: "ICMP"}

        data = {
            "id": self.rule_data.get("id"), # Передаем ID, если он был (редактирование)
            "action": action_map.get(self.comboBox_2.currentIndex()),
            "proto": proto_map.get(self.comboBox.currentIndex()),
            "src": self.lineEdit.text().strip() or "any", # "any" если пусто
            "sport": self.lineEdit_2.text().strip() or "any",
            "dst": self.lineEdit_3.text().strip() or "any",
            "dport": self.lineEdit_4.text().strip() or "any",
            # "description": self.descriptionLineEdit.text().strip() # Если добавите поле
        }
        # Проверка корректности
        if not data["action"] or not data["proto"]:
            QMessageBox.warning(self, "Ошибка ввода", "Необходимо выбрать Действие и Протокол.")
            return None
        # TODO: Добавить более строгую валидацию IP, портов

        return data

# --- Основная логика Фаервола ---
class FirewallLogic:
    def __init__(self):
        self._is_enabled = self.check_firewall_status_sync() # Проверяем статус при инициализации
        # Словари/списки для хранения временных данных или настроек
        self.firewall_logging_settings = self.load_log_settings() # Загружаем настройки
        self.unlogged_ips = set(self.firewall_logging_settings.get("unlogged_ips", []))
        self.unlogged_ports = set(str(p) for p in self.firewall_logging_settings.get("unlogged_ports", [])) # Порты как строки
        self.log_folder = self.firewall_logging_settings.get("log_folder", "/var/log/myfirewall") # Папка для логов
        # Создаем папку, если ее нет
        try:
            os.makedirs(self.log_folder, exist_ok=True)
            # Проверяем права на запись (упрощенно)
            if not os.access(self.log_folder, os.W_OK):
                 print(f"Предупреждение: Нет прав на запись в папку логов {self.log_folder}")
        except OSError as e:
            print(f"Ошибка создания папки логов {self.log_folder}: {e}")

        # Настройка логирования Python
        self.log_file_path = os.path.join(self.log_folder, "firewall_actions.log")
        logging.basicConfig(filename=self.log_file_path,
                            level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        print(f"Логирование настроено в файл: {self.log_file_path}")

    def _run_command(self, command_list):
        """ Вспомогательная функция для запуска команд с sudo """
        # ВНИМАНИЕ: Убедитесь, что пользователь имеет право выполнять iptables/conntrack через sudo без пароля,
        # либо запускайте весь скрипт через sudo.
        command = ['sudo'] + command_list
        print(f"Выполнение команды: {' '.join(command)}")
        try:
            # Используем shlex.join для безопасного отображения, если нужно
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=5) # check=False, чтобы обработать ошибки самим
            if result.returncode != 0:
                error_msg = f"Ошибка выполнения команды {' '.join(command_list)}: {result.stderr or result.stdout}"
                print(error_msg)
                logging.error(error_msg)
                return None, result.stderr or result.stdout # Возвращаем None и ошибку
            logging.info(f"Команда {' '.join(command_list)} выполнена успешно. Вывод: {result.stdout[:100]}...") # Логируем часть вывода
            return result.stdout, None # Возвращаем вывод и None как маркер отсутствия ошибки
        except FileNotFoundError:
            error_msg = f"Ошибка: Команда 'sudo' или '{command_list[0]}' не найдена. Убедитесь, что они установлены и доступны в PATH."
            print(error_msg)
            logging.error(error_msg)
            return None, error_msg
        except subprocess.TimeoutExpired:
             error_msg = f"Ошибка: Команда {' '.join(command_list)} выполнялась слишком долго."
             print(error_msg)
             logging.error(error_msg)
             return None, error_msg
        except Exception as e:
            error_msg = f"Неожиданная ошибка при выполнении {' '.join(command_list)}: {e}"
            print(error_msg)
            logging.error(error_msg)
            return None, str(e)

    def check_firewall_status_sync(self):
        """ Синхронная проверка статуса (используется в __init__) """
        # Простой способ: проверяем политику по умолчанию для INPUT
        stdout, error = self._run_command(['iptables', '-L', 'INPUT', '-n'])
        if stdout and "policy DROP" in stdout:
            return True
        # Дополнительная проверка (если политика ACCEPT, но есть правила) - очень упрощенно
        elif stdout and "ACCEPT" not in stdout and "DROP" not in stdout and "REJECT" not in stdout:
             # Возможно, правила есть, считаем включенным (нужна лучшая логика)
             return True
        return False

    def is_enabled(self):
        print("Backend: Checking firewall status...")
        # Можно вызывать синхронный метод или реализовать асинхронную проверку
        # self._is_enabled = self.check_firewall_status_sync() # Обновляем перед возвратом
        return self._is_enabled

    def enable_firewall(self):
        print("Backend: Enabling firewall...")
        # Устанавливаем политики по умолчанию
        _, err1 = self._run_command(['iptables', '-P', 'INPUT', 'DROP'])
        _, err2 = self._run_command(['iptables', '-P', 'FORWARD', 'DROP'])
        _, err3 = self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT']) # Разрешаем исходящие
        # Разрешаем loopback
        _, err4 = self._run_command(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
        _, err5 = self._run_command(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'])
        # Разрешаем установленные соединения
        _, err6 = self._run_command(['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])

        if any([err1, err2, err3, err4, err5, err6]):
            logging.error("Не удалось полностью включить фаервол.")
            # Можно попытаться откатить изменения, но это сложно
            return False
        else:
            self._is_enabled = True
            logging.info("Фаервол успешно включен.")
            return True

    def disable_firewall(self):
        print("Backend: Disabling firewall...")
        # Устанавливаем разрешающие политики
        _, err1 = self._run_command(['iptables', '-P', 'INPUT', 'ACCEPT'])
        _, err2 = self._run_command(['iptables', '-P', 'FORWARD', 'ACCEPT'])
        _, err3 = self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        # Сбрасываем все правила
        _, err4 = self._run_command(['iptables', '-F']) # Flush all rules

        if any([err1, err2, err3, err4]):
            logging.error("Не удалось полностью выключить фаервол.")
            return False
        else:
            self._is_enabled = False
            logging.info("Фаервол успешно выключен.")
            return True

    def get_rules(self):
        print("Backend: Getting rules...")
        # ВНИМАНИЕ: Очень упрощенный парсер! Не обрабатывает сложные правила, цепочки, модули.
        stdout, error = self._run_command(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
        if error or not stdout:
            return [] # Возвращаем пустой список при ошибке

        rules = []
        lines = stdout.strip().split('\n')
        if len(lines) < 3: # Ожидаем заголовок, разделитель и хотя бы одно правило/политику
            return []

        for line in lines[2:]: # Пропускаем заголовок и строку Chain INPUT
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue # Пропускаем строки без номера или пустые

            try:
                rule = {"id": int(parts[0]), "enabled": True} # Считаем все видимые правила включенными
                rule["action"] = parts[1] # target
                rule["proto"] = parts[2] # prot
                # Очень примитивное определение источника/назначения/портов
                # Нужно парсить опции типа --dport, -s, -d и т.д.
                rule["src"] = "any"
                rule["sport"] = "any"
                rule["dst"] = "any"
                rule["dport"] = "any"
                rule["description"] = "" # Описание не получить из iptables -L

                # Попытка извлечь dport для простых правил
                for i, part in enumerate(parts):
                    if part == "dpt:": # или --dport
                        rule["dport"] = parts[i+1] if i+1 < len(parts) else "n/a"
                        break
                    if part == "spt:": # или --sport
                        rule["sport"] = parts[i+1] if i+1 < len(parts) else "n/a"
                        break
                # Попытка извлечь src/dst
                if len(parts) > 4: rule["src"] = parts[4]
                if len(parts) > 5: rule["dst"] = parts[5]


                rules.append(rule)
            except (IndexError, ValueError) as e:
                print(f"Ошибка парсинга строки правила: '{line}' -> {e}")
                logging.warning(f"Ошибка парсинга строки правила: '{line}' -> {e}")

        return rules

    def delete_rule(self, rule_id):
        print(f"Backend: Deleting rule with ID: {rule_id}")
        # ВАЖНО: ID здесь - это номер строки в выводе iptables -L --line-numbers
        # Он может меняться при добавлении/удалении других правил!
        # Для надежности лучше использовать хендлы nftables или более сложную логику.
        stdout, error = self._run_command(['iptables', '-D', 'INPUT', str(rule_id)])
        if error:
            logging.error(f"Не удалось удалить правило ID {rule_id}: {error}")
            return False
        logging.info(f"Удалено правило ID {rule_id}.")
        return True

    def add_edit_rule(self, rule_data):
        cmd = ['iptables']
        rule_id = rule_data.get("id")

        if rule_id: # Редактирование
            print(f"Backend: Editing rule: {rule_data}")
            cmd.extend(['-R', 'INPUT', str(rule_id)]) # Заменяем по номеру строки (ID)
        else: # Добавление
            print(f"Backend: Adding new rule: {rule_data}")
            cmd.extend(['-A', 'INPUT']) # Добавляем в конец

        # Собираем команду
        if rule_data.get("proto") and rule_data["proto"] != 'any':
             cmd.extend(['-p', rule_data["proto"].lower()]) # iptables хочет протокол в нижнем регистре
        if rule_data.get("src") and rule_data["src"] != 'any':
             cmd.extend(['-s', rule_data["src"]])
        if rule_data.get("sport") and rule_data["sport"] != 'any':
             cmd.extend(['--sport', rule_data["sport"]])
        if rule_data.get("dst") and rule_data["dst"] != 'any':
             cmd.extend(['-d', rule_data["dst"]])
        if rule_data.get("dport") and rule_data["dport"] != 'any':
             cmd.extend(['--dport', rule_data["dport"]])

        # Действие
        action = rule_data.get("action")
        if action:
            cmd.extend(['-j', action])
        else:
            logging.error("Действие для правила не указано.")
            return False # Нельзя добавить правило без действия

        stdout, error = self._run_command(cmd)
        if error:
            logging.error(f"Не удалось {'изменить' if rule_id else 'добавить'} правило: {error}")
            return False
        logging.info(f"Правило успешно {'изменено' if rule_id else 'добавлено'}: {' '.join(cmd)}")
        return True

    def get_connections(self):
        print("Backend: Getting connections...")
        # Требует 'conntrack-tools'
        stdout, error = self._run_command(['conntrack', '-L'])
        if error or not stdout:
            print("Не удалось получить список соединений. Убедитесь, что conntrack-tools установлен.")
            logging.warning("Не удалось получить список соединений (conntrack -L).")
            return []

        connections = []
        lines = stdout.strip().split('\n')
        for line in lines:
            parts = line.split()
            if not parts: continue
            try:
                proto = parts[0]
                state = "UNKNOWN"
                local_ip, local_port, remote_ip, remote_port = "n/a", "n/a", "n/a", "n/a"

                # Очень упрощенный парсинг вывода conntrack
                for part in parts:
                    if part.startswith("src="): local_ip = part.split("=")[1]
                    elif part.startswith("dst="): remote_ip = part.split("=")[1]
                    elif part.startswith("sport="): local_port = part.split("=")[1]
                    elif part.startswith("dport="): remote_port = part.split("=")[1]
                    elif part.upper() in ["ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE_WAIT", "LISTEN", "NONE"]: # Добавить другие состояния
                        state = part.upper()

                connections.append({
                    "local": f"{local_ip}:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}",
                    "proto": proto.upper(),
                    "state": state,
                    "raw": line # Сохраняем сырую строку для terminate_connection
                })
            except Exception as e:
                print(f"Ошибка парсинга строки conntrack: '{line}' -> {e}")
                logging.warning(f"Ошибка парсинга строки conntrack: '{line}' -> {e}")
        return connections

    def terminate_connection(self, connection_data):
        print(f"Backend: Terminating connection: {connection_data}")
        # Требует 'conntrack-tools'
        # Извлекаем данные из connection_data или используем 'raw' строку, если парсинг был ненадежным
        # Пример извлечения (может потребовать улучшения)
        try:
            local_parts = connection_data['local'].split(':')
            remote_parts = connection_data['remote'].split(':')
            local_ip = local_parts[0]
            local_port = local_parts[1]
            remote_ip = remote_parts[0]
            remote_port = remote_parts[1]
            proto = connection_data['proto'].lower()

            cmd = ['conntrack', '-D',
                   '-p', proto,
                   '-s', local_ip, '--sport', local_port,
                   '-d', remote_ip, '--dport', remote_port]

            stdout, error = self._run_command(cmd)
            if error:
                logging.error(f"Не удалось разорвать соединение: {error}")
                return False
            logging.info(f"Соединение разорвано: {connection_data}")
            return True
        except Exception as e:
            error_msg = f"Ошибка при формировании команды conntrack -D: {e}"
            print(error_msg)
            logging.error(error_msg)
            return False

    def load_log_settings(self):
        # Загрузка настроек из файла (например, JSON)
        # Если файла нет, возвращаем дефолтные
        settings_file = "firewall_settings.json"
        default_settings = {
            "log_approved": True, "log_prohibited": True, "log_rejected": False,
            "log_tcp": True, "log_udp": True, "log_icmp": True,
            "unlogged_ips": ["127.0.0.1"], "unlogged_ports": [123],
            "log_folder": "/var/log/myfirewall" # Убедитесь, что папка существует и есть права
        }
        try:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    # Обновляем дефолтные настройки загруженными, чтобы сохранить новые ключи
                    default_settings.update(loaded_settings)
                    print("Настройки логирования загружены из файла.")
                    return default_settings
            else:
                 print("Файл настроек не найден, используются значения по умолчанию.")
                 return default_settings
        except (json.JSONDecodeError, IOError) as e:
            print(f"Ошибка загрузки настроек из {settings_file}: {e}. Используются значения по умолчанию.")
            return default_settings

    def save_log_settings(self):
        # Сохранение текущих настроек в файл
        settings_file = "firewall_settings.json"
        try:
            with open(settings_file, 'w') as f:
                json.dump(self.firewall_logging_settings, f, indent=4)
            print("Настройки логирования сохранены в файл.")
            logging.info("Настройки логирования сохранены.")
            return True
        except IOError as e:
            error_msg = f"Ошибка сохранения настроек в {settings_file}: {e}"
            print(error_msg)
            logging.error(error_msg)
            return False

    def update_log_settings(self, settings):
        print(f"Backend: Updating log settings: {settings}")
        # TODO: Реализовать логику применения настроек логирования
        # Например, добавление/удаление правил iptables с таргетом LOG
        # Это сложная задача, т.к. требует генерации правил на основе чекбоксов
        # и списков нелоггируемых IP/портов. Пока просто сохраняем.
        self.firewall_logging_settings.update(settings)
        self.unlogged_ips = set(self.firewall_logging_settings.get("unlogged_ips", []))
        self.unlogged_ports = set(str(p) for p in self.firewall_logging_settings.get("unlogged_ports", []))
        self.log_folder = self.firewall_logging_settings.get("log_folder", "/var/log/myfirewall")
        # Перенастроить логирование Python, если папка изменилась (упрощенно)
        self.log_file_path = os.path.join(self.log_folder, "firewall_actions.log")
        # (В реальном приложении нужно более аккуратно перенастраивать logging)
        return self.save_log_settings() # Сохраняем в файл

    def get_log_settings(self):
        print("Backend: Getting log settings...")
        # Возвращаем текущие настройки из памяти (они загружены при инициализации)
        # Добавляем актуальные списки
        self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
        self.firewall_logging_settings["unlogged_ports"] = sorted(list(self.unlogged_ports), key=int) # Сортируем порты как числа
        self.firewall_logging_settings["log_folder"] = self.log_folder
        return self.firewall_logging_settings

    def get_recent_actions(self, limit=10):
         print(f"Backend: Getting recent actions (limit {limit})...")
         # Читаем последние строки из лог-файла
         try:
             if not os.path.exists(self.log_file_path):
                 return ["Лог-файл не найден."]
             with open(self.log_file_path, 'r') as f:
                 # Читаем все строки, берем последние 'limit'
                 lines = f.readlines()
                 return [line.strip() for line in lines[-limit:]]
         except IOError as e:
             error_msg = f"Ошибка чтения лог-файла {self.log_file_path}: {e}"
             print(error_msg)
             logging.error(error_msg)
             return [f"Ошибка чтения лога: {e}"]

    def add_unlogged_ip(self, ip):
        print(f"Backend: Adding unlogged IP: {ip}")
        # TODO: Добавить валидацию IP
        self.unlogged_ips.add(ip)
        self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
        # TODO: Обновить правила логирования iptables/nftables
        return self.save_log_settings() # Сохраняем

    def add_unlogged_port(self, port):
         print(f"Backend: Adding unlogged port: {port}")
         # Валидация была в GUI
         self.unlogged_ports.add(str(port))
         self.firewall_logging_settings["unlogged_ports"] = sorted(list(self.unlogged_ports), key=int)
         # TODO: Обновить правила логирования iptables/nftables
         return self.save_log_settings() # Сохраняем

    def remove_unlogged_ip(self, ip):
        print(f"Backend: Removing unlogged IP: {ip}")
        if ip in self.unlogged_ips:
            self.unlogged_ips.discard(ip)  # Используем discard, чтобы не было ошибки, если IP уже удален
            self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
            # TODO: Обновить правила логирования iptables/nftables
            return self.save_log_settings()  # Сохраняем
        else:
            print(f"IP {ip} не найден в списке нелоггируемых.")
            return True  # Считаем операцию успешной, т.к. IP и так нет

    def remove_unlogged_port(self, port_str):
        print(f"Backend: Removing unlogged port: {port_str}")
        if port_str in self.unlogged_ports:
            self.unlogged_ports.discard(port_str)
            # Сохраняем порты как числа
            self.firewall_logging_settings["unlogged_ports"] = sorted(
                [int(p) for p in self.unlogged_ports if p.isdigit()], key=int)
            # TODO: Обновить правила логирования iptables/nftables
            return self.save_log_settings()  # Сохраняем
        else:
            print(f"Порт {port_str} не найден в списке нелоггируемых.")
            return True
# --- Конец FirewallLogic ---

# --- Основное окно ---
class MainWindow(QMainWindow):
    def __init__(self):
        # Проверка прав суперпользователя (очень базово)
        if os.geteuid() != 0:
             QMessageBox.critical(None, "Ошибка прав", "Для работы фаервола необходимы права суперпользователя (root).\nПожалуйста, запустите приложение с помощью sudo.")
             sys.exit(1)

        super().__init__()

        # Загружаем UI из файла
        try:
            loadUi("firewall_main.ui", self)
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", "Не найден файл firewall_main.ui")
            sys.exit(1)
        except Exception as e:
             QMessageBox.critical(self, "Ошибка загрузки UI", f"Произошла ошибка: {e}")
             sys.exit(1)

        self.setWindowTitle("Фаервол") # Устанавливаем заголовок окна

        # Создаем экземпляр логики
        self.firewall_logic = FirewallLogic()
        self.log_folder_path = self.firewall_logic.log_folder # Храним путь к папке логов

        # Модели для QListView
        #self.recent_actions_model = QStringListModel()
        #self.unlogged_ips_model = QStringListModel()
        #self.unlogged_ports_model = QStringListModel()

        # --- Настройка виджетов ---
        self.setup_widgets()

        # --- Подключение сигналов к слотам ---
        self.connect_signals()

        # --- Инициализация начального состояния ---
        self.initialize_ui_state()

    def setup_widgets(self):
        # Настройка таблицы правил
        self.listOfRules.setColumnCount(9) # Убедись, что это соответствует твоему UI или логике
        self.listOfRules.setHorizontalHeaderLabels(
            ["Номер", "Вкл/Выкл", "Действие", "Протокол", "Источник", "Порт ист.", "Назначение", "Порт назн.", "Описание"]
        )
        self.listOfRules.horizontalHeader().setStretchLastSection(True)
        self.listOfRules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfRules.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfRules.setSelectionMode(QAbstractItemView.SingleSelection)
        self.listOfRules.setColumnWidth(0, 50); self.listOfRules.setColumnWidth(1, 60)
        self.listOfRules.setColumnWidth(2, 80); self.listOfRules.setColumnWidth(3, 70)

        # Настройка таблицы подключений
        self.listOfConnections.setColumnCount(4)
        self.listOfConnections.setHorizontalHeaderLabels(
             ["Локальный IP:Порт", "Удаленный IP:Порт", "Протокол", "Состояние"]
        )
        self.listOfConnections.horizontalHeader().setStretchLastSection(True)
        self.listOfConnections.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfConnections.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfConnections.setSelectionMode(QAbstractItemView.SingleSelection)

        # Настройка QListWidget для логов
        # (Удалена установка моделей, так как используются QListWidget)
        self.unloggedIPListWidget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.unloggedPortListWidget.setSelectionMode(QAbstractItemView.SingleSelection)

        # УДАЛЕН блок программного добавления self.log_folder_label
        # Предполагается, что QLabel с именем logFolderPathLabel создан в Qt Designer

        print("Настройка виджетов завершена.")



    def connect_signals(self):
        # --- Вкладка "Общее" ---
        self.stateButton.clicked.connect(self.toggle_firewall_state)

        # --- Вкладка "Правила" ---
        self.addeditRuleButton.clicked.connect(self.open_add_edit_rule_dialog) # Слот без аргумента для кнопки "Добавить"
        self.deleteRuleButton.clicked.connect(self.delete_selected_rule)
        self.listOfRules.itemSelectionChanged.connect(self.update_rule_buttons_state)
        self.listOfRules.itemDoubleClicked.connect(self.open_add_edit_rule_dialog_for_selected) # Слот для двойного клика

        # --- Вкладка "Подключения" ---
        self.terminateConnectionButton.clicked.connect(self.terminate_selected_connection)
        self.listOfConnections.itemSelectionChanged.connect(self.update_connection_buttons_state)

        # --- Вкладка "Логи" ---
        self.approvedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.prohibitedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.rejectedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.tcpPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.udpPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.icmpPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.addIpButton.clicked.connect(self.add_unlogged_ip)
        self.addPortButton.clicked.connect(self.add_unlogged_port)
        self.chooseFolderButton.clicked.connect(self.choose_log_folder)

        self.removeIpButton.clicked.connect(self.remove_selected_unlogged_ip)
        self.removePortButton.clicked.connect(self.remove_selected_unlogged_port)

    def initialize_ui_state(self):
        self.update_firewall_status_ui()
        self.load_and_display_rules()
        self.load_and_display_connections()
        self.load_and_display_log_settings()
        # self.load_and_display_recent_actions() # Вызывается в update_firewall_status_ui
        self.update_rule_buttons_state()
        self.update_connection_buttons_state()

    # --- Слоты для обработки сигналов ---

    # --- Вкладка "Общее" ---
    @pyqtSlot()
    def toggle_firewall_state(self):
        print("Сигнал: toggle_firewall_state сработал")
        # ВАЖНО: Выполнять в отдельном потоке в реальном приложении!
        if self.firewall_logic.is_enabled():
            if self.firewall_logic.disable_firewall():
                print("Фаервол выключен")
            else:
                 QMessageBox.warning(self, "Ошибка", "Не удалось выключить фаервол")
        else:
            if self.firewall_logic.enable_firewall():
                print("Фаервол включен")
            else:
                 QMessageBox.warning(self, "Ошибка", "Не удалось включить фаервол")
        self.update_firewall_status_ui() # Обновляем UI после выполнения

    def update_firewall_status_ui(self):
        # ВАЖНО: Получение статуса тоже может быть долгим, лучше в потоке!
        is_enabled = self.firewall_logic.is_enabled() # Получаем актуальный статус
        if is_enabled:
            self.stateButton.setText("Выключить")
            self.firewallWork.setText("Работа фаервола: <font color='green'>Включен</font>")
            print("UI Обновлен: Фаервол ВКЛ")
        else:
            self.stateButton.setText("Включить")
            self.firewallWork.setText("Работа фаервола: <font color='red'>Выключен</font>")
            print("UI Обновлен: Фаервол ВЫКЛ")
        self.load_and_display_recent_actions() # Обновляем последние действия при смене статуса

    def load_and_display_recent_actions(self):
        print("Загрузка последних действий...")
        actions = self.firewall_logic.get_recent_actions()
        # Работа с QListWidget:
        self.recentActionsListWidget.clear()  # Очищаем список
        self.recentActionsListWidget.addItems(actions)  # Добавляем строки
        print("Последние действия отображены.")

    # --- Вкладка "Правила" ---
    # Слот для кнопки "Добавить/редактировать правило" - вызывает диалог для ДОБАВЛЕНИЯ
    @pyqtSlot()
    def open_add_edit_rule_dialog(self):
         print("Сигнал: open_add_edit_rule_dialog (Добавление)")
         self._show_rule_dialog() # Вызываем внутренний метод без данных

    # Слот для двойного клика по строке - вызывает диалог для РЕДАКТИРОВАНИЯ
    @pyqtSlot(QTableWidgetItem)
    def open_add_edit_rule_dialog_for_selected(self, item):
         print("Сигнал: Двойной клик по строке правила (Редактирование)")
         selected_row = item.row()
         if selected_row >= 0:
             rule_id = self.listOfRules.item(selected_row, 0).data(Qt.UserRole)
             if rule_id is None:
                  try: rule_id = int(self.listOfRules.item(selected_row, 0).text())
                  except (ValueError, AttributeError): rule_id = None

             if rule_id is not None:
                 # Получаем данные правила из ТАБЛИЦЫ (упрощенно, лучше из бэкенда по ID)
                 rule_data = {"id": rule_id}
                 try:
                      rule_data["enabled"] = self.listOfRules.cellWidget(selected_row, 1).findChild(QCheckBox).isChecked()
                      rule_data["action"] = self.listOfRules.item(selected_row, 2).text()
                      rule_data["proto"] = self.listOfRules.item(selected_row, 3).text()
                      rule_data["src"] = self.listOfRules.item(selected_row, 4).text()
                      rule_data["sport"] = self.listOfRules.item(selected_row, 5).text()
                      rule_data["dst"] = self.listOfRules.item(selected_row, 6).text()
                      rule_data["dport"] = self.listOfRules.item(selected_row, 7).text()
                      # rule_data["description"] = self.listOfRules.item(selected_row, 8).text() # Если столбец есть
                 except AttributeError:
                      print("Предупреждение: Не удалось полностью прочитать данные правила из таблицы для редактирования.")
                      # Можно попытаться запросить полные данные из бэкенда по ID
                      # rule_data = self.firewall_logic.get_rule_details(rule_id) # Пример

                 self._show_rule_dialog(rule_data) # Вызываем внутренний метод с данными
             else:
                  QMessageBox.warning(self, "Ошибка", "Не удалось определить ID правила для редактирования.")

    def _show_rule_dialog(self, rule_data=None):
        """ Внутренний метод для показа диалога добавления/редактирования """
        dialog = AddEditRuleDialog(self, rule_data) # Передаем rule_data
        if dialog.exec_() == QDialog.Accepted: # Показываем диалог и ждем результат
            new_rule_data = dialog.get_data() # Получаем данные из диалога
            if new_rule_data:
                 # ВАЖНО: Выполнять в отдельном потоке!
                 if self.firewall_logic.add_edit_rule(new_rule_data):
                      QMessageBox.information(self, "Успех", f"Правило успешно {'изменено' if new_rule_data.get('id') else 'добавлено'}.")
                      self.load_and_display_rules() # Обновляем таблицу
                 else:
                      QMessageBox.critical(self, "Ошибка", f"Не удалось {'изменить' if new_rule_data.get('id') else 'добавить'} правило.")
        else:
             print("Добавление/редактирование правила отменено.")

    @pyqtSlot()
    def delete_selected_rule(self):
        print("Сигнал: delete_selected_rule сработал")
        # ... (код удаления остался прежним, но вызов firewall_logic.delete_rule В ПОТОК!)
        selected_items = self.listOfRules.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано правило для удаления.")
            return
        selected_row = selected_items[0].row()
        rule_id_item = self.listOfRules.item(selected_row, 0)
        if rule_id_item:
            rule_id = rule_id_item.data(Qt.UserRole)
            if rule_id is None:
                 try: rule_id = int(rule_id_item.text())
                 except ValueError: rule_id = None

            if rule_id is None:
                 QMessageBox.critical(self, "Ошибка", "Не удалось определить ID правила.")
                 return

            reply = QMessageBox.question(self, 'Подтверждение', f"Удалить правило ID {rule_id}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                # ВАЖНО: Выполнять в отдельном потоке!
                if self.firewall_logic.delete_rule(rule_id):
                    print(f"Правило ID {rule_id} удалено")
                    self.load_and_display_rules()
                else:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить правило ID {rule_id}.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось получить ID правила.")

    @pyqtSlot()
    def update_rule_buttons_state(self):
        has_selection = len(self.listOfRules.selectedItems()) > 0
        self.deleteRuleButton.setEnabled(has_selection)

    def load_and_display_rules(self):
        print("Загрузка и отображение правил...")
        # ВАЖНО: Выполнять в отдельном потоке!
        rules = self.firewall_logic.get_rules()
        self.listOfRules.setRowCount(0) # Очищаем таблицу перед заполнением
        self.listOfRules.setRowCount(len(rules))

        for row_index, rule in enumerate(rules):
            item_id = QTableWidgetItem(str(rule.get("id", "")))
            item_id.setData(Qt.UserRole, rule.get("id"))

            item_enabled_widget = QWidget()
            chk_enabled = QCheckBox()
            chk_enabled.setChecked(rule.get("enabled", False)) # Enabled пока не используется в логике iptables
            chk_enabled.setProperty("rule_id", rule.get("id"))
            chk_enabled.toggled.connect(self.toggle_rule_enabled_state)
            layout = QVBoxLayout(item_enabled_widget)
            layout.addWidget(chk_enabled); layout.setAlignment(Qt.AlignCenter); layout.setContentsMargins(0,0,0,0)
            # item_enabled_widget.setLayout(layout) # Не обязательно

            item_action = QTableWidgetItem(rule.get("action", "")); item_proto = QTableWidgetItem(rule.get("proto", ""))
            item_src = QTableWidgetItem(rule.get("src", "")); item_sport = QTableWidgetItem(rule.get("sport", ""))
            item_dst = QTableWidgetItem(rule.get("dst", "")); item_dport = QTableWidgetItem(rule.get("dport", ""))
            item_desc = QTableWidgetItem(rule.get("description", ""))

            self.listOfRules.setItem(row_index, 0, item_id)
            self.listOfRules.setCellWidget(row_index, 1, item_enabled_widget)
            self.listOfRules.setItem(row_index, 2, item_action); self.listOfRules.setItem(row_index, 3, item_proto)
            self.listOfRules.setItem(row_index, 4, item_src); self.listOfRules.setItem(row_index, 5, item_sport)
            self.listOfRules.setItem(row_index, 6, item_dst); self.listOfRules.setItem(row_index, 7, item_dport)
            self.listOfRules.setItem(row_index, 8, item_desc)

        self.update_rule_buttons_state()

    @pyqtSlot(bool)
    def toggle_rule_enabled_state(self):
         sender_checkbox = self.sender()
         if sender_checkbox:
             rule_id = sender_checkbox.property("rule_id")
             is_enabled = sender_checkbox.isChecked()
             print(f"Сигнал: toggle_rule_enabled_state для правила ID {rule_id}, новое состояние: {is_enabled}")
             # TODO: Реализовать логику включения/выключения правила в FirewallLogic
             # Это может быть сложнее, чем просто добавить/удалить правило.
             # Возможно, потребуется комментировать/раскомментировать правила,
             # или перемещать их между цепочками. Пока не реализовано.
             QMessageBox.information(self, "Инфо", "Функция включения/выключения правила пока не реализована в бэкенде.")
             # Вернуть чекбокс в прежнее состояние, если бэкенд не смог изменить
             # sender_checkbox.setChecked(not is_enabled)

    # --- Вкладка "Подключения" ---
    @pyqtSlot()
    def terminate_selected_connection(self):
        print("Сигнал: terminate_selected_connection сработал")
        # ... (код остался прежним, но вызов firewall_logic.terminate_connection В ПОТОК!)
        selected_items = self.listOfConnections.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано соединение для разрыва.")
            return
        selected_row = selected_items[0].row()
        try:
            connection_data = { "local": self.listOfConnections.item(selected_row, 0).text(),
                                "remote": self.listOfConnections.item(selected_row, 1).text(),
                                "proto": self.listOfConnections.item(selected_row, 2).text(),
                                "state": self.listOfConnections.item(selected_row, 3).text(), }
        except AttributeError:
             QMessageBox.critical(self, "Ошибка", "Не удалось получить данные.")
             return

        reply = QMessageBox.question(self, 'Подтверждение', f"Разорвать соединение:\n{connection_data['local']} <-> {connection_data['remote']}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            # ВАЖНО: Выполнять в отдельном потоке!
            if self.firewall_logic.terminate_connection(connection_data):
                 print(f"Соединение разорвано: {connection_data}")
                 self.load_and_display_connections()
            else:
                 QMessageBox.critical(self, "Ошибка", f"Не удалось разорвать соединение.")

    @pyqtSlot()
    def update_connection_buttons_state(self):
        has_selection = len(self.listOfConnections.selectedItems()) > 0
        self.terminateConnectionButton.setEnabled(has_selection)

    def load_and_display_connections(self):
        print("Загрузка и отображение соединений...")
        # ВАЖНО: Выполнять в отдельном потоке!
        connections = self.firewall_logic.get_connections()
        self.listOfConnections.setRowCount(0) # Очищаем
        self.listOfConnections.setRowCount(len(connections))

        for row_index, conn in enumerate(connections):
            item_local = QTableWidgetItem(conn.get("local", "")); item_remote = QTableWidgetItem(conn.get("remote", ""))
            item_proto = QTableWidgetItem(conn.get("proto", "")); item_state = QTableWidgetItem(conn.get("state", ""))
            self.listOfConnections.setItem(row_index, 0, item_local); self.listOfConnections.setItem(row_index, 1, item_remote)
            self.listOfConnections.setItem(row_index, 2, item_proto); self.listOfConnections.setItem(row_index, 3, item_state)

        self.update_connection_buttons_state()

    # --- Вкладка "Логи" ---
    @pyqtSlot(bool)
    def update_logging_config_from_checkbox(self, checked):
         print(f"Сигнал: update_logging_config_from_checkbox, состояние: {checked}")
         self.save_current_log_settings()

    def save_current_log_settings(self):
        # Получаем списки из QListWidget
        # Используем list comprehension для получения всех элементов
        unlogged_ips = [self.unloggedIPListWidget.item(i).text() for i in range(self.unloggedIPListWidget.count())]
        unlogged_ports_str = [self.unloggedPortListWidget.item(i).text() for i in
                              range(self.unloggedPortListWidget.count())]

        # Преобразуем порты в числа для сохранения (с проверкой)
        unlogged_ports_int = []
        for p_str in unlogged_ports_str:
            if p_str.isdigit():
                unlogged_ports_int.append(int(p_str))
            else:
                print(f"Предупреждение: Нечисловое значение '{p_str}' в списке портов проигнорировано при сохранении.")

        settings = {
            "log_approved": self.approvedPackets.isChecked(),
            "log_prohibited": self.prohibitedPackets.isChecked(),
            "log_rejected": self.rejectedPackets.isChecked(),
            "log_tcp": self.tcpPackets.isChecked(),
            "log_udp": self.udpPackets.isChecked(),
            "log_icmp": self.icmpPackets.isChecked(),
            "unlogged_ips": sorted(unlogged_ips),  # Сохраняем отсортированный список строк
            "unlogged_ports": sorted(unlogged_ports_int),  # Сохраняем отсортированный список чисел
            "log_folder": self.log_folder_path  # Используем сохраненный путь
        }
        # ВАЖНО: Выполнять в отдельном потоке (если обновление настроек долгое)!
        if not self.firewall_logic.update_log_settings(settings):
            QMessageBox.warning(self, "Ошибка", "Не удалось сохранить настройки логирования.")
        else:
            print("Настройки логирования сохранены")

    def load_and_display_log_settings(self):
        print("Загрузка и отображение настроек логов...")
        # ВАЖНО: Выполнять в отдельном потоке (если загрузка долгая)!
        settings = self.firewall_logic.get_log_settings()

        # Блокируем сигналы на время установки состояния чекбоксов
        self.approvedPackets.blockSignals(True); self.prohibitedPackets.blockSignals(True)
        self.rejectedPackets.blockSignals(True); self.tcpPackets.blockSignals(True)
        self.udpPackets.blockSignals(True); self.icmpPackets.blockSignals(True)

        self.approvedPackets.setChecked(settings.get("log_approved", False))
        self.prohibitedPackets.setChecked(settings.get("log_prohibited", False))
        self.rejectedPackets.setChecked(settings.get("log_rejected", False))
        self.tcpPackets.setChecked(settings.get("log_tcp", False))
        self.udpPackets.setChecked(settings.get("log_udp", False))
        self.icmpPackets.setChecked(settings.get("log_icmp", False))

        # Разблокируем сигналы
        self.approvedPackets.blockSignals(False); self.prohibitedPackets.blockSignals(False)
        self.rejectedPackets.blockSignals(False); self.tcpPackets.blockSignals(False)
        self.udpPackets.blockSignals(False); self.icmpPackets.blockSignals(False)

        # Отображаем списки в QListWidget
        self.unloggedIPListWidget.clear()
        self.unloggedIPListWidget.addItems(settings.get("unlogged_ips", []))
        self.unloggedIPListWidget.sortItems() # Сортируем IP

        self.unloggedPortListWidget.clear()
        # Порты отображаем как строки, сортируем как числа
        ports_str = [str(p) for p in settings.get("unlogged_ports", [])]
        self.unloggedPortListWidget.addItems(sorted(ports_str, key=int))

        # Отображаем путь к папке логов в метке из UI
        self.log_folder_path = settings.get("log_folder", "/var/log/myfirewall")
        # Убедись, что имя 'logFolderPathLabel' совпадает с objectName в Qt Designer
        if hasattr(self, 'logFolderPathLabel'):
             self.logFolderPathLabel.setText(f"Папка логов: {self.log_folder_path}")
        else:
             print("Предупреждение: QLabel 'logFolderPathLabel' не найден в UI для обновления пути к логам.")
        print("Настройки логирования загружены и отображены (с QListWidget).")


    @pyqtSlot()
    def add_unlogged_ip(self):
        print("Сигнал: add_unlogged_ip сработал")
        ip_address = self.lineEdit.text().strip()
        if not ip_address:
            return QMessageBox.warning(self, "Внимание", "Введите IP-адрес.")
        # Простая валидация формата IP
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            return QMessageBox.warning(self, "Ошибка", "Некорректный формат IP-адреса.")

        # Проверка на дубликат прямо в виджете
        items = self.unloggedIPListWidget.findItems(ip_address, Qt.MatchExactly)
        if items:
            return QMessageBox.information(self, "Информация", f"IP-адрес {ip_address} уже есть в списке.")

        # ВАЖНО: Выполнять в отдельном потоке!
        if self.firewall_logic.add_unlogged_ip(ip_address):
            print(f"Добавлен IP: {ip_address}")
            self.lineEdit.clear()
            # Обновляем список в UI
            self.unloggedIPListWidget.addItem(ip_address)
            self.unloggedIPListWidget.sortItems()  # Сортируем
        else:
            QMessageBox.warning(self, "Ошибка", f"Не удалось добавить IP-адрес {ip_address} в настройки.")

    @pyqtSlot()
    def add_unlogged_port(self):
        print("Сигнал: add_unlogged_port сработал")
        port_str = self.lineEdit_2.text().strip()
        if not port_str:
            return QMessageBox.warning(self, "Внимание", "Введите номер порта.")
        try:
            port = int(port_str)
            if not 0 <= port <= 65535: raise ValueError("Порт вне допустимого диапазона (0-65535)")
        except ValueError as e:
            return QMessageBox.warning(self, "Ошибка", f"Некорректный номер порта: {e}")

        # Проверка на дубликат прямо в виджете
        items = self.unloggedPortListWidget.findItems(port_str, Qt.MatchExactly)
        if items:
            return QMessageBox.information(self, "Информация", f"Порт {port_str} уже есть в списке.")

        # ВАЖНО: Выполнять в отдельном потоке!
        if self.firewall_logic.add_unlogged_port(port):  # Передаем int в логику
            print(f"Добавлен порт: {port}")
            self.lineEdit_2.clear()
            # Обновляем список в UI
            self.unloggedPortListWidget.addItem(port_str)
            # Сортировка портов как чисел
            all_ports = [self.unloggedPortListWidget.item(i).text() for i in range(self.unloggedPortListWidget.count())]
            self.unloggedPortListWidget.clear()
            self.unloggedPortListWidget.addItems(sorted(all_ports, key=int))
        else:
            QMessageBox.warning(self, "Ошибка", f"Не удалось добавить порт {port} в настройки.")

    @pyqtSlot()
    @pyqtSlot()
    def choose_log_folder(self):
        print("Сигнал: choose_log_folder сработал")
        # Начинаем диалог с текущей сохраненной папки
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку для логов", self.log_folder_path)
        if folder_path:
            print(f"Выбрана папка: {folder_path}")
            self.log_folder_path = folder_path  # Обновляем путь в атрибуте класса
            # Обновляем текст метки в UI
            if hasattr(self, 'logFolderPathLabel'):
                self.logFolderPathLabel.setText(f"Папка логов: {self.log_folder_path}")
            else:
                print("Предупреждение: QLabel 'logFolderPathLabel' не найден в UI для обновления пути.")
            # Сохраняем новые настройки (включая путь)
            self.save_current_log_settings()

    @pyqtSlot()
    def remove_selected_unlogged_ip(self):
        print("Сигнал: remove_selected_unlogged_ip сработал")
        selected_item = self.unloggedIPListWidget.currentItem()  # Получаем выделенный элемент
        if not selected_item:
            QMessageBox.warning(self, "Внимание", "Выберите IP-адрес для удаления.")
            return

        ip_address = selected_item.text()
        reply = QMessageBox.question(self, 'Подтверждение',
                                     f"Вы уверены, что хотите удалить IP '{ip_address}' из списка нелоггируемых?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # ВАЖНО: Выполнять в отдельном потоке!
            if self.firewall_logic.remove_unlogged_ip(ip_address):  # Нужен этот метод в FirewallLogic
                print(f"Удален IP: {ip_address}")
                self.load_and_display_log_settings()  # Обновляем список
            else:
                QMessageBox.warning(self, "Ошибка", f"Не удалось удалить IP-адрес {ip_address}.")

    @pyqtSlot()
    def remove_selected_unlogged_port(self):
        print("Сигнал: remove_selected_unlogged_port сработал")
        selected_item = self.unloggedPortListWidget.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Внимание", "Выберите порт для удаления.")
            return

        port_str = selected_item.text()
        reply = QMessageBox.question(self, 'Подтверждение',
                                     f"Вы уверены, что хотите удалить порт '{port_str}' из списка нелоггируемых?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # ВАЖНО: Выполнять в отдельном потоке!
            if self.firewall_logic.remove_unlogged_port(port_str):  # Нужен этот метод в FirewallLogic
                print(f"Удален порт: {port_str}")
                self.load_and_display_log_settings()  # Обновляем список
            else:
                QMessageBox.warning(self, "Ошибка", f"Не удалось удалить порт {port_str}.")

if __name__ == '__main__':
    # Настройка логирования Python ДО создания QApplication
    # (можно настроить здесь или оставить в FirewallLogic.__init__)
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    # Если хочешь лог и в консоль тоже:
    # logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))


    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())