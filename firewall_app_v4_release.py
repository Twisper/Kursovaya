import sys
import json
import subprocess
import re # Для базового парсинга
import shlex # Для безопасного формирования команд
import os # Для проверки прав
import logging
import functools

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QLabel, QListView,
    QTableWidget, QTabWidget, QCheckBox, QLineEdit, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QMessageBox, QFileDialog, QVBoxLayout,
    QDialog, QDialogButtonBox # Добавлено для диалога
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem # Для QListView
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, Qt, QStringListModel, QThread, pyqtSignal, QObject, QTimer # Добавлено для QListView

# --- Класс для диалога добавления/редактирования ---
class BaseWorker(QThread):
    """ Базовый класс для всех воркеров, чтобы не дублировать сигналы """
    error_occurred = pyqtSignal(str) # Сигнал об ошибке
    # Сигнал finished уже есть в QThread, но можно определить свой, если нужна доп. информация

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        # Этот метод должен быть переопределен в дочерних классах
        raise NotImplementedError

# --- Воркеры для фоновых задач ---
class RulesWorker(BaseWorker):
    rules_ready = pyqtSignal(list) # Список правил
    operation_successful = pyqtSignal(str) # Сообщение об успехе операции

    def __init__(self, firewall_logic, operation, data=None):
        super().__init__()
        self.firewall_logic = firewall_logic
        self.operation = operation # Например, "get", "delete", "add_edit", "toggle_enabled"
        self.data = data # Данные для операции (rule_id, rule_data)

    def run(self):
        try:
            if self.operation == "get":
                rules = self.firewall_logic.get_rules()
                self.rules_ready.emit(rules)
            elif self.operation == "delete":
                if self.firewall_logic.delete_rule(self.data): # data это rule_id
                    self.operation_successful.emit(f"Правило ID {self.data} удалено.")
                else:
                    self.error_occurred.emit(f"Не удалось удалить правило ID {self.data}.")
            elif self.operation == "add_edit":
                if self.firewall_logic.add_edit_rule(self.data): # data это rule_data
                    op_type = "изменено" if self.data.get("id") else "добавлено"
                    self.operation_successful.emit(f"Правило успешно {op_type}.")
                else:
                    op_type = "изменить" if self.data.get("id") else "добавить"
                    self.error_occurred.emit(f"Не удалось {op_type} правило.")
            elif self.operation == "toggle_enabled": # Новый тип операции
                 rule_id = self.data.get("rule_id")
                 is_enabled = self.data.get("is_enabled")
                 if self.firewall_logic.set_rule_enabled_state(rule_id, is_enabled): # Новый метод
                      self.operation_successful.emit(f"Состояние правила ID {rule_id} изменено.")
                 else:
                      self.error_occurred.emit(f"Не удалось изменить состояние правила ID {rule_id}.")
            else:
                self.error_occurred.emit(f"Неизвестная операция для правил: {self.operation}")
        except Exception as e:
            self.error_occurred.emit(f"Ошибка в RulesWorker ({self.operation}): {e}")

class ConnectionWorker(BaseWorker):
    connections_ready = pyqtSignal(list)
    operation_successful = pyqtSignal(str)

    def __init__(self, firewall_logic, operation, data=None):
        super().__init__()
        self.firewall_logic = firewall_logic
        self.operation = operation # "get", "terminate"
        self.data = data # connection_data для terminate

    def run(self):
        try:
            if self.operation == "get":
                connections = self.firewall_logic.get_connections()
                self.connections_ready.emit(connections)
            elif self.operation == "terminate":
                if self.firewall_logic.terminate_connection(self.data):
                    self.operation_successful.emit("Соединение разорвано.")
                else:
                    self.error_occurred.emit("Не удалось разорвать соединение.")
            else:
                self.error_occurred.emit(f"Неизвестная операция для соединений: {self.operation}")
        except Exception as e:
            self.error_occurred.emit(f"Ошибка в ConnectionWorker ({self.operation}): {e}")

class StatusWorker(BaseWorker):
    status_ready = pyqtSignal(bool) # True если включен, False если выключен
    operation_successful = pyqtSignal(str)

    def __init__(self, firewall_logic, operation):
        super().__init__()
        self.firewall_logic = firewall_logic
        self.operation = operation # "get", "enable", "disable"

    def run(self):
        try:
            if self.operation == "get":
                status = self.firewall_logic.is_enabled_sync() # Синхронный вызов
                self.status_ready.emit(status)
            elif self.operation == "enable":
                if self.firewall_logic.enable_firewall():
                    self.operation_successful.emit("Фаервол включен.")
                else:
                    self.error_occurred.emit("Не удалось включить фаервол.")
            elif self.operation == "disable":
                if self.firewall_logic.disable_firewall():
                    self.operation_successful.emit("Фаервол выключен.")
                else:
                    self.error_occurred.emit("Не удалось выключить фаервол.")
            else:
                self.error_occurred.emit(f"Неизвестная операция для статуса: {self.operation}")
        except Exception as e:
            self.error_occurred.emit(f"Ошибка в StatusWorker ({self.operation}): {e}")

class LogWorker(BaseWorker):
    recent_actions_ready = pyqtSignal(list)
    log_settings_ready = pyqtSignal(dict)
    operation_successful = pyqtSignal(str) # Для сохранения настроек, добавления IP/порта

    def __init__(self, firewall_logic, operation, data=None):
        super().__init__()
        self.firewall_logic = firewall_logic
        self.operation = operation # "get_recent", "get_settings", "update_settings", "add_ip", "add_port", "remove_ip", "remove_port"
        self.data = data

    def run(self):
        try:
            if self.operation == "get_recent":
                actions = self.firewall_logic.get_recent_actions()
                self.recent_actions_ready.emit(actions)
            elif self.operation == "get_settings":
                settings = self.firewall_logic.get_log_settings()
                self.log_settings_ready.emit(settings)
            elif self.operation == "update_settings":
                if self.firewall_logic.update_log_settings(self.data):
                    self.operation_successful.emit("Настройки логирования сохранены.")
                else:
                    self.error_occurred.emit("Не удалось сохранить настройки логирования.")
            elif self.operation == "add_ip":
                if self.firewall_logic.add_unlogged_ip(self.data): # data это ip_address
                    self.operation_successful.emit(f"IP {self.data} добавлен в нелоггируемые.")
                else:
                    self.error_occurred.emit(f"Не удалось добавить IP {self.data}.")
            elif self.operation == "add_port":
                if self.firewall_logic.add_unlogged_port(self.data): # data это port
                    self.operation_successful.emit(f"Порт {self.data} добавлен в нелоггируемые.")
                else:
                    self.error_occurred.emit(f"Не удалось добавить порт {self.data}.")
            elif self.operation == "remove_ip":
                if self.firewall_logic.remove_unlogged_ip(self.data):
                    self.operation_successful.emit(f"IP {self.data} удален из нелоггируемых.")
                else:
                    self.error_occurred.emit(f"Не удалось удалить IP {self.data}.")
            elif self.operation == "remove_port":
                if self.firewall_logic.remove_unlogged_port(self.data):
                    self.operation_successful.emit(f"Порт {self.data} удален из нелоггируемых.")
                else:
                    self.error_occurred.emit(f"Не удалось удалить порт {self.data}.")
            else:
                self.error_occurred.emit(f"Неизвестная операция для логов: {self.operation}")
        except Exception as e:
            self.error_occurred.emit(f"Ошибка в LogWorker ({self.operation}): {e}")

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
        self.defined_rules_file = "defined_firewall_rules.json"
        self._is_enabled = self.is_enabled_sync() # Проверяем реальный статус при запуске
        self.defined_rules = self.load_defined_rules()

        self.firewall_logging_settings = self.load_log_settings_from_file()
        self.unlogged_ips = set(self.firewall_logging_settings.get("unlogged_ips", []))
        self.unlogged_ports = set(str(p) for p in self.firewall_logging_settings.get("unlogged_ports", []))
        self.log_folder = self.firewall_logging_settings.get("log_folder", "/var/log/myfirewall")
        try:
            os.makedirs(self.log_folder, exist_ok=True)
            if not os.access(self.log_folder, os.W_OK):
                 print(f"Предупреждение: Нет прав на запись в папку логов {self.log_folder}")
        except OSError as e:
            print(f"Ошибка создания папки логов {self.log_folder}: {e}")

        self.log_file_path = os.path.join(self.log_folder, "firewall_actions.log")
        # Настройка логирования Python
        log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler = logging.FileHandler(self.log_file_path)
        file_handler.setFormatter(log_formatter)
        # Удаляем предыдущие хендлеры, чтобы избежать дублирования логов при перезапуске (если __main__ настраивает)
        # logging.getLogger().handlers = []
        if not logging.getLogger().hasHandlers(): # Добавляем, только если нет хендлеров
            logging.getLogger().addHandler(file_handler)
            logging.getLogger().setLevel(logging.INFO)

        print(f"Логирование настроено в файл: {self.log_file_path}")

        if self._is_enabled:
            print("Фаервол был активен при запуске, применяем определенные правила...")
            self.apply_all_defined_rules_to_iptables()


    def _run_command(self, command_list):
        command = ['sudo'] + command_list
        print(f"Выполнение команды: {' '.join(shlex.quote(c) for c in command)}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
            if result.returncode != 0:
                error_msg = f"Ошибка команды {' '.join(command_list)}: {result.stderr.strip() or result.stdout.strip()}"
                print(error_msg); logging.error(error_msg)
                return None, error_msg
            logging.info(f"Команда {' '.join(command_list)} -> {result.stdout.strip()[:200]}")
            return result.stdout.strip(), None
        except FileNotFoundError:
            error_msg = f"Команда 'sudo' или '{command_list[0]}' не найдена."
            print(error_msg); logging.error(error_msg)
            return None, error_msg
        except subprocess.TimeoutExpired:
             error_msg = f"Таймаут команды {' '.join(command_list)}."
             print(error_msg); logging.error(error_msg)
             return None, error_msg
        except Exception as e:
            error_msg = f"Исключение при выполнении {' '.join(command_list)}: {e}"
            print(error_msg); logging.error(error_msg)
            return None, str(e)

    def load_defined_rules(self):
        default_rules = []
        try:
            if os.path.exists(self.defined_rules_file):
                with open(self.defined_rules_file, 'r') as f:
                    rules = json.load(f)
                print(f"Правила загружены из {self.defined_rules_file}")
                processed = []
                next_id = 1
                seen_ids = set()
                for r in rules:
                    rid = r.get("id")
                    if rid is None or not isinstance(rid, int) or rid in seen_ids:
                        while next_id in seen_ids: next_id +=1
                        r["id"] = next_id
                    seen_ids.add(r["id"])
                    if r["id"] >= next_id: next_id = r["id"] + 1
                    if "enabled" not in r: r["enabled"] = True # По умолчанию включены
                    # Добавляем описание, если нет
                    if "description" not in r: r["description"] = ""
                    processed.append(r)
                return processed
            else:
                self.save_defined_rules_internal(default_rules)
                return default_rules
        except (json.JSONDecodeError, IOError) as e:
            print(f"Ошибка загрузки правил: {e}. Используется пустой список."); logging.error(f"Ошибка загрузки правил: {e}")
            return default_rules

    def save_defined_rules_internal(self, rules_to_save):
        try:
            with open(self.defined_rules_file, 'w') as f:
                json.dump(rules_to_save, f, indent=4)
            print(f"Правила сохранены в {self.defined_rules_file}")
            return True
        except IOError as e:
            print(f"Ошибка сохранения правил: {e}"); logging.error(f"Ошибка сохранения правил: {e}")
            return False

    def save_defined_rules(self):
        return self.save_defined_rules_internal(self.defined_rules)

    def get_next_rule_id(self):
        if not self.defined_rules: return 1
        return max(r.get("id", 0) for r in self.defined_rules) + 1

    def is_enabled_sync(self):
        stdout, _ = self._run_command(['iptables', '-S', 'INPUT']) # -S показывает правила в формате добавления
        # Проверяем, есть ли политика DROP и базовые правила
        if stdout:
            if "P INPUT DROP" in stdout and "-A INPUT -i lo -j ACCEPT" in stdout and "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT" in stdout:
                 return True
        return False

    def _apply_single_rule_to_iptables(self, rule_data_orig, operation="add"):
        """
        Применяет (добавляет или удаляет) ОДНО правило в iptables.
        rule_data_orig: Словарь с данными правила.
        operation: "add" для добавления, "delete" для удаления.
        Возвращает True в случае успеха, False в случае ошибки.
        """
        # Работаем с копией, чтобы не изменять оригинальный словарь,
        # если он будет нужен для отката в вызывающем методе.
        rule_data = rule_data_orig.copy()

        # Базовая команда iptables
        cmd_base = ['iptables']

        # Определяем флаг операции для iptables и текстовое описание для логов
        if operation == "add":
            iptables_operation_flag = '-A'  # Добавить в конец цепочки
            log_operation_description = "добавления"
        elif operation == "delete":
            iptables_operation_flag = '-D'  # Удалить первое найденное совпадение
            log_operation_description = "удаления"
        else:
            logging.error(f"FirewallLogic: Неизвестная операция '{operation}' для правила ID {rule_data.get('id')}")
            return False

        # Собираем параметры правила в список (кроме флага операции и имени цепочки)
        # Эти параметры будут использоваться как для добавления, так и для удаления (и для проверки -C)
        rule_parameters = []
        # Протокол
        proto = rule_data.get("proto", "any").lower() # Приводим к нижнему регистру
        if proto != 'any':
             rule_parameters.extend(['-p', proto])
        # Источник IP
        src_ip = rule_data.get("src", "any")
        if src_ip.lower() != 'any': # Приводим к нижнему регистру для сравнения
             rule_parameters.extend(['-s', src_ip])
        # Порт источника
        sport = str(rule_data.get("sport", "any")).lower() # Приводим к строке и нижнему регистру
        if sport != 'any':
             rule_parameters.extend(['--sport', sport])
        # Назначение IP
        dst_ip = rule_data.get("dst", "any")
        if dst_ip.lower() != 'any':
             rule_parameters.extend(['-d', dst_ip])
        # Порт назначения
        dport = str(rule_data.get("dport", "any")).lower()
        if dport != 'any':
             rule_parameters.extend(['--dport', dport])

        # Другие параметры (например, интерфейс), если они есть в rule_data:
        # if rule_data.get("in_interface"):
        #     rule_parameters.extend(['-i', rule_data.get("in_interface")])
        # if rule_data.get("out_interface"):
        #     rule_parameters.extend(['-o', rule_data.get("out_interface")])

        # Действие (target)
        target_action = rule_data.get("action")
        if target_action:
            rule_parameters.extend(['-j', target_action.upper()]) # Действия обычно в UPPERCASE
        else:
            # Если это операция добавления, действие обязательно.
            # При удалении, если действие не указано, iptables может удалить правило,
            # совпадающее по остальным параметрам, если такое существует без явного -j.
            # Но для консистентности лучше всегда иметь target.
            if operation == "add":
                logging.error(f"FirewallLogic: Действие (target) для правила ID {rule_data.get('id')} не указано. Невозможно добавить.")
                return False
            # Если удаление и нет target, попробуем удалить без -j, но это менее надежно.
            # Пока оставляем как есть: если нет target, то и удалить по этому описанию не получится точно.
            logging.warning(f"FirewallLogic: Действие (target) для правила ID {rule_data.get('id')} не указано. Удаление может быть неточным.")


        # Формируем полную команду для iptables (пока работаем только с цепочкой INPUT)
        # ВАЖНО: Если ты планируешь использовать другие цепочки (FORWARD, OUTPUT, пользовательские),
        # имя цепочки нужно будет передавать или определять динамически.
        chain_name = "INPUT"
        final_iptables_command = cmd_base + [iptables_operation_flag, chain_name] + rule_parameters

        logging.info(f"FirewallLogic: Попытка {log_operation_description} правила ID {rule_data.get('id')} командой: {' '.join(final_iptables_command)}")

        # Специальная обработка для операции удаления:
        # `iptables -D` вернет ошибку (ненулевой код), если правило не найдено.
        # Мы хотим считать это "успешным" удалением отсутствующего правила.
        if operation == "delete":
            # Сначала проверим, существует ли правило с помощью `iptables -C` (check)
            # Команда -C должна точно совпадать с правилом, как оно было бы добавлено.
            check_command_params = ['-C', chain_name] + rule_parameters
            _, error_check = self._run_command(cmd_base + check_command_params)

            if error_check:
                # Если -C вернуло ошибку, значит, правила с такими параметрами нет.
                # Сообщение об ошибке от -C часто "iptables: No chain/target/match by that name."
                logging.info(f"FirewallLogic: Правило ID {rule_data.get('id')} для удаления не найдено в iptables (проверка -C). Считаем 'удаленным'. Ошибка проверки: {error_check}")
                return True # Его и так нет, значит, цель "удалить" достигнута.

        # Выполняем основную команду (добавление или удаление существующего)
        stdout, error_execution = self._run_command(final_iptables_command)

        if error_execution:
            logging.error(f"FirewallLogic: Ошибка при выполнении '{' '.join(final_iptables_command)}': {error_execution}")
            return False
        else:
            logging.info(f"FirewallLogic: Команда iptables '{' '.join(final_iptables_command)}' выполнена успешно.")
            return True

    def apply_all_defined_rules_to_iptables(self):
        if not self._is_enabled: return False
        print("Применение всех активных правил в iptables...")
        # Базовая очистка (опасно, если есть другие правила)
        self._run_command(['iptables', '-F', 'INPUT'])
        self._run_command(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
        self._run_command(['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])

        success = True
        for rule in self.defined_rules:
            if rule.get("enabled"):
                if not self._apply_single_rule_to_iptables(rule, "add"):
                    success = False
        return success

    def enable_firewall(self):
        print("Backend: Включение фаервола...")
        _, err1 = self._run_command(['iptables', '-P', 'INPUT', 'DROP'])
        _, err2 = self._run_command(['iptables', '-P', 'FORWARD', 'DROP'])
        _, err3 = self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        if any([err1, err2, err3]): logging.error("Не удалось установить политики."); return False
        self._is_enabled = True # Устанавливаем флаг ДО применения правил
        if self.apply_all_defined_rules_to_iptables():
            logging.info("Фаервол включен, правила применены.")
            return True
        else:
            logging.warning("Фаервол включен, но не все правила применены.")
            return True # Возвращаем True, т.к. базовый фаервол включен

    def disable_firewall(self):
        print("Backend: Выключение фаервола...")
        # Сначала удаляем наши правила, чтобы не мешать смене политик
        self._run_command(['iptables', '-F', 'INPUT'])
        self._run_command(['iptables', '-F', 'FORWARD'])

        _, err1 = self._run_command(['iptables', '-P', 'INPUT', 'ACCEPT'])
        _, err2 = self._run_command(['iptables', '-P', 'FORWARD', 'ACCEPT'])
        _, err3 = self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        if any([err1, err2, err3]): logging.error("Не удалось выключить фаервол."); return False
        self._is_enabled = False
        logging.info("Фаервол выключен.")
        return True

    def get_rules(self):
        print("Backend: Отдаем defined_rules в UI...")
        return sorted(self.defined_rules, key=lambda r: r.get("id", 0))

    def add_edit_rule(self, rule_data_from_dialog):
        is_new = "id" not in rule_data_from_dialog or rule_data_from_dialog["id"] is None
        rule_data_from_dialog["enabled"] = rule_data_from_dialog.get("enabled", True) # Убедимся, что enabled есть

        if is_new:
            rule_data_from_dialog["id"] = self.get_next_rule_id()
            self.defined_rules.append(rule_data_from_dialog.copy()) # Сохраняем копию
            log_op = "добавлено"
        else:
            idx_found = -1
            old_rule = None
            for i, r in enumerate(self.defined_rules):
                if r.get("id") == rule_data_from_dialog["id"]:
                    idx_found = i
                    old_rule = r.copy() # Для удаления старой версии из iptables
                    break
            if idx_found == -1: logging.error(f"Правило ID {rule_data_from_dialog['id']} не найдено."); return False
            # Обновляем правило в списке
            self.defined_rules[idx_found].update(rule_data_from_dialog)
            log_op = "изменено"
            # Если старое правило было включено и фаервол активен, удаляем его из iptables
            if self._is_enabled and old_rule and old_rule.get("enabled"):
                 self._apply_single_rule_to_iptables(old_rule, "delete")

        # Применяем новое/измененное правило в iptables, если оно включено и фаервол активен
        if self._is_enabled and self.defined_rules[idx_found if not is_new else -1].get("enabled"):
            if not self._apply_single_rule_to_iptables(self.defined_rules[idx_found if not is_new else -1], "add"):
                logging.warning(f"Правило {log_op}, но не применено в iptables.")
                # Не откатываем, сохраняем в конфиг как есть

        if self.save_defined_rules():
            logging.info(f"Правило ID {rule_data_from_dialog['id']} {log_op} и сохранено."); return True
        return False

    def delete_rule(self, rule_id):
        idx_to_del = -1
        rule_to_del_data = None
        for i, r in enumerate(self.defined_rules):
            if r.get("id") == rule_id:
                idx_to_del = i
                rule_to_del_data = r.copy()
                break
        if idx_to_del == -1: logging.error(f"Правило ID {rule_id} для удаления не найдено."); return False

        # Если правило было активно и фаервол включен, удаляем из iptables
        if self._is_enabled and rule_to_del_data.get("enabled"):
            self._apply_single_rule_to_iptables(rule_to_del_data, "delete")

        del self.defined_rules[idx_to_del]
        if self.save_defined_rules(): logging.info(f"Правило ID {rule_id} удалено."); return True
        self.defined_rules.insert(idx_to_del, rule_to_del_data) # Откат
        logging.error(f"Правило ID {rule_id} удалено, но НЕ сохранено."); return False


    def set_rule_enabled_state(self, rule_id, is_enabled_new_state):
        idx_to_toggle = -1
        for i, r in enumerate(self.defined_rules):
            if r.get("id") == rule_id:
                idx_to_toggle = i
                break
        if idx_to_toggle == -1: logging.error(f"Правило ID {rule_id} не найдено."); return False

        rule_data = self.defined_rules[idx_to_toggle]
        if rule_data.get("enabled") == is_enabled_new_state: return True # Состояние не изменилось

        applied_to_iptables = True
        if self._is_enabled: # Только если фаервол включен, трогаем iptables
            if is_enabled_new_state: # Включаем
                applied_to_iptables = self._apply_single_rule_to_iptables(rule_data, "add")
            else: # Выключаем (удаляем из iptables)
                applied_to_iptables = self._apply_single_rule_to_iptables(rule_data, "delete")

        if applied_to_iptables:
            self.defined_rules[idx_to_toggle]["enabled"] = is_enabled_new_state
            if self.save_defined_rules():
                logging.info(f"Состояние правила ID {rule_id} -> {is_enabled_new_state}"); return True
            else: # Не удалось сохранить, откатываем enabled
                self.defined_rules[idx_to_toggle]["enabled"] = not is_enabled_new_state
                # Попытка откатить iptables (сложно, если правило было добавлено/удалено)
                logging.error(f"Состояние правила ID {rule_id} изменено, но НЕ сохранено."); return False
        else: # Не удалось применить к iptables
            logging.error(f"Не удалось изменить состояние правила ID {rule_id} в iptables."); return False

    def get_connections(self): # Парсер остается упрощенным
        stdout, error = self._run_command(['conntrack', '-L'])
        if error or not stdout: logging.warning("Не удалось получить соединения (conntrack)."); return []
        connections = []
        for line in stdout.strip().split('\n'):
            parts = line.split()
            if not parts: continue
            try:
                proto = parts[0]; state = "N/A"
                l_ip, l_port, r_ip, r_port = "n/a", "n/a", "n/a", "n/a"
                for p in parts:
                    if p.startswith("src="): l_ip = p.split("=")[1]
                    elif p.startswith("dst="): r_ip = p.split("=")[1]
                    elif p.startswith("sport="): l_port = p.split("=")[1]
                    elif p.startswith("dport="): r_port = p.split("=")[1]
                    elif p.upper() in ["ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE", "LISTEN", "NONE", "RELATED", "NEW"]: state = p.upper()
                connections.append({"local": f"{l_ip}:{l_port}", "remote": f"{r_ip}:{r_port}", "proto": proto.upper(), "state": state, "raw": line})
            except Exception as e: logging.warning(f"Парсинг conntrack: '{line}' -> {e}")
        return connections

    def terminate_connection(self, connection_data):
        print(f"Backend: Terminating connection: {connection_data}")
        try:
            local_full = connection_data['local']
            remote_full = connection_data['remote']
            proto_lower = connection_data['proto'].lower()

            local_ip, local_port_str = local_full.split(':')
            remote_ip, remote_port_str = remote_full.split(':')

            # Проверяем, что порты - числа
            if not local_port_str.isdigit() or not remote_port_str.isdigit():
                logging.error(f"Некорректные порты в connection_data: {connection_data}")
                return False

            cmd1 = ['conntrack', '-D',
                    '-p', proto_lower,
                    '-s', local_ip, '--sport', local_port_str,
                    '-d', remote_ip, '--dport', remote_port_str]

            cmd2 = ['conntrack', '-D',  # Команда для обратного направления
                    '-p', proto_lower,
                    '-s', remote_ip, '--sport', remote_port_str,  # Меняем src и dst местами
                    '-d', local_ip, '--dport', local_port_str]

            stdout1, error1 = self._run_command(cmd1)
            # Даже если первая команда вернула "0 flow entries", пробуем вторую
            stdout2, error2 = self._run_command(cmd2)

            # Считаем успех, если хотя бы одна команда что-то удалила
            # или если обе не нашли записей (возможно, соединение уже закрыто)
            # "0 flow entries" - это не ошибка выполнения команды, а результат.
            # Ошибка будет, если returncode != 0 ИЛИ error1/error2 не None.

            if error1 and "0 flow entries" not in error1:  # Реальная ошибка при первой команде
                logging.error(f"Ошибка при попытке разорвать соединение (направление 1): {error1}")
                # Можно проверить error2 тоже, но если первая команда сфейлилась не из-за "0 flow", то это проблема
                return False
            if error2 and "0 flow entries" not in error2:  # Реальная ошибка при второй команде
                logging.error(f"Ошибка при попытке разорвать соединение (направление 2): {error2}")
                return False

            # Если обе команды вернули "0 flow entries", соединение, вероятно, уже закрыто.
            # Если хотя бы одна не вернула "0 flow entries" (т.е. что-то удалила или был другой вывод)
            # И при этом не было других ошибок (returncode !=0), то считаем успехом.
            deleted1 = stdout1 and "0 flow entries" not in stdout1  # Что-то было в stdout1, и это не "0 flow"
            deleted2 = stdout2 and "0 flow entries" not in stdout2

            if deleted1 or deleted2:
                logging.info(f"Соединение успешно разорвано (или одна из его записей): {connection_data}")
                return True
            elif (error1 and "0 flow entries" in error1) and \
                    (error2 and "0 flow entries" in error2):
                logging.info(
                    f"Записи для соединения {connection_data} не найдены в conntrack (возможно, уже закрыто). Считаем разрыв успешным.")
                return True  # Если обе команды сказали "0 flow entries", вероятно, оно уже закрыто
            else:
                # Сюда мы попадем, если были какие-то другие сообщения в stdout, но не ошибки
                logging.warning(
                    f"Разрыв соединения {connection_data} вернул неожиданный результат. stdout1: {stdout1}, stdout2: {stdout2}")
                return False  # Или True, в зависимости от того, как строго мы хотим это оценивать

        except Exception as e:
            error_msg = f"Исключение при формировании/выполнении команды conntrack -D: {e}"
            print(error_msg)
            logging.error(error_msg)
            return False

    def load_log_settings_from_file(self): # Переименовал, чтобы отличать
        settings_file = "firewall_log_settings.json"
        defaults = {"log_approved": True, "log_prohibited": True, "log_rejected": False,
                    "log_tcp": True, "log_udp": True, "log_icmp": True,
                    "unlogged_ips": ["127.0.0.1"], "unlogged_ports": [123],
                    "log_folder": "/var/log/myfirewall"}
        try:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    loaded = json.load(f); defaults.update(loaded)
                print("Настройки логирования загружены.")
            return defaults
        except (json.JSONDecodeError, IOError) as e:
            print(f"Ошибка загрузки настроек логов: {e}. Дефолт."); logging.error(f"Ошибка логов: {e}")
            return defaults

    def save_log_settings_to_file(self):
        settings_file = "firewall_log_settings.json"
        try:
            with open(settings_file, 'w') as f:
                json.dump(self.firewall_logging_settings, f, indent=4)
            print("Настройки логирования сохранены."); logging.info("Настройки логирования сохранены.")
            return True
        except IOError as e: print(f"Ошибка сохр. логов: {e}"); logging.error(f"Ошибка сохр. логов: {e}"); return False

    def update_log_settings(self, settings):
        print(f"Backend: Обновление настроек логирования: {settings}")
        self.firewall_logging_settings.update(settings)
        self.unlogged_ips = set(self.firewall_logging_settings.get("unlogged_ips", []))
        self.unlogged_ports = set(str(p) for p in self.firewall_logging_settings.get("unlogged_ports", []))
        new_log_folder = self.firewall_logging_settings.get("log_folder", self.log_folder)
        if new_log_folder != self.log_folder:
             self.log_folder = new_log_folder
             try: os.makedirs(self.log_folder, exist_ok=True)
             except OSError as e: print(f"Ошибка создания папки логов {self.log_folder}: {e}")
             self.log_file_path = os.path.join(self.log_folder, "firewall_actions.log")
             # Перенастройка logging (упрощенно, может потребовать удаления старых хендлеров)
             logging.basicConfig(filename=self.log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', force=True) # force=True (Python 3.8+)
        # TODO: Применить настройки к правилам логирования iptables (очень сложно)
        return self.save_log_settings_to_file()

    def get_log_settings(self):
        # Обновляем списки перед возвратом
        self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
        self.firewall_logging_settings["unlogged_ports"] = sorted([int(p) for p in self.unlogged_ports if p.isdigit()], key=int)
        self.firewall_logging_settings["log_folder"] = self.log_folder
        return self.firewall_logging_settings

    def get_recent_actions(self, limit=20): # Увеличил лимит
        try:
            if not os.path.exists(self.log_file_path): return ["Лог-файл не найден."]
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines(); return [l.strip() for l in lines[-limit:]]
        except IOError as e: print(f"Ошибка чтения лога: {e}"); logging.error(f"Ошибка лога: {e}"); return [f"Ошибка лога: {e}"]

    def add_unlogged_ip(self, ip):
        self.unlogged_ips.add(ip)
        self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
        return self.save_log_settings_to_file()

    def remove_unlogged_ip(self, ip):
        self.unlogged_ips.discard(ip)
        self.firewall_logging_settings["unlogged_ips"] = sorted(list(self.unlogged_ips))
        return self.save_log_settings_to_file()

    def add_unlogged_port(self, port_int):
        self.unlogged_ports.add(str(port_int))
        self.firewall_logging_settings["unlogged_ports"] = sorted([int(p) for p in self.unlogged_ports if p.isdigit()], key=int)
        return self.save_log_settings_to_file()

    def remove_unlogged_port(self, port_str):
        self.unlogged_ports.discard(port_str)
        self.firewall_logging_settings["unlogged_ports"] = sorted([int(p) for p in self.unlogged_ports if p.isdigit()], key=int)
        return self.save_log_settings_to_file()
# --- Конец FirewallLogic ---

# --- Основное окно ---
class MainWindow(QMainWindow):
    def __init__(self):
        if os.geteuid() != 0:
            # Показываем QMessageBox перед созданием основного окна
            # Для этого создаем временное QApplication, если оно еще не создано
            temp_app_created = False
            if QApplication.instance() is None:
                _ = QApplication(sys.argv) # Создаем временное
                temp_app_created = True
            QMessageBox.critical(None, "Ошибка прав", "Для работы фаервола необходимы права суперпользователя (root).\nПожалуйста, запустите приложение с помощью sudo.")
            if temp_app_created:
                 QApplication.quit() # Закрываем временное приложение
            sys.exit(1)

        super().__init__()
        try: loadUi("firewall_main.ui", self)
        except Exception as e: QMessageBox.critical(self, "Ошибка UI", f"{e}"); sys.exit(1)

        self.setWindowTitle("Мой Фаервол")
        self.firewall_logic = FirewallLogic()
        self.log_folder_path = self.firewall_logic.log_folder # Инициализируем

        self.active_workers = {} # Для отслеживания активных воркеров {name: worker_instance}

        self.setup_widgets()
        self.connect_signals()
        self.initialize_ui_state()

        # Таймеры для периодического обновления
        self.connections_timer = QTimer(self)
        self.connections_timer.timeout.connect(self.request_connections_update)
        self.connections_timer.start(5000) # Каждые 5 секунд

        self.recent_actions_timer = QTimer(self)
        self.recent_actions_timer.timeout.connect(self.request_recent_actions_update)
        self.recent_actions_timer.start(10000) # Каждые 10 секунд

    def _start_worker(self, worker_name, worker_class, *args, **kwargs):
        """ Вспомогательный метод для запуска воркера и отслеживания """
        if worker_name in self.active_workers and self.active_workers[worker_name].isRunning():
            print(f"Воркер '{worker_name}' уже запущен. Пропускаем.")
            return None # или можно вернуть существующий воркер

        # Если есть старый завершенный воркер с таким именем, удаляем его
        if worker_name in self.active_workers:
             self.active_workers[worker_name].deleteLater() # Планируем удаление

        worker = worker_class(*args, **kwargs)
        self.active_workers[worker_name] = worker
        # Общий обработчик завершения для очистки
        worker.finished.connect(lambda name=worker_name: self.active_workers.pop(name, None))
        worker.finished.connect(worker.deleteLater)
        worker.start()
        return worker

    def setup_widgets(self): # Остается как в твоем последнем варианте, но убедись что QListWidget, а не ListView
        self.listOfRules.setColumnCount(9)
        self.listOfRules.setHorizontalHeaderLabels(["Номер", "Вкл/Выкл", "Действие", "Протокол", "Источник", "Порт ист.", "Назначение", "Порт назн.", "Описание"])
        self.listOfRules.horizontalHeader().setStretchLastSection(True)
        self.listOfRules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfRules.setSelectionBehavior(QAbstractItemView.SelectRows); self.listOfRules.setSelectionMode(QAbstractItemView.SingleSelection)
        self.listOfRules.setColumnWidth(0, 40); self.listOfRules.setColumnWidth(1, 60); self.listOfRules.setColumnWidth(2, 70); self.listOfRules.setColumnWidth(3, 60)

        self.listOfConnections.setColumnCount(4)
        self.listOfConnections.setHorizontalHeaderLabels(["Локальный IP:Порт", "Удаленный IP:Порт", "Протокол", "Состояние"])
        self.listOfConnections.horizontalHeader().setStretchLastSection(True)
        self.listOfConnections.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfConnections.setSelectionBehavior(QAbstractItemView.SelectRows); self.listOfConnections.setSelectionMode(QAbstractItemView.SingleSelection)

        self.unloggedIPListWidget.setSelectionMode(QAbstractItemView.SingleSelection) # Изменил на QListWidget
        self.unloggedPortListWidget.setSelectionMode(QAbstractItemView.SingleSelection) # Изменил на QListWidget
        self.recentActionsListWidget.setSelectionMode(QAbstractItemView.NoSelection) # Изменил на QListWidget

        # Метка для пути к логам (предполагается, что она есть в UI с именем logFolderPathLabel)
        if not hasattr(self, 'logFolderPathLabel'):
             # Если ее нет в UI, создаем и добавляем программно (упрощенно)
             self.logFolderPathLabel = QLabel("Папка логов: не указана")
             # Попытка добавить на вкладку (может потребовать layout в Designer)
             layout = self.tab_4.layout()
             if layout: layout.addWidget(self.logFolderPathLabel)
             else: print("Предупреждение: Нет layout на вкладке логов для logFolderPathLabel")

        print("Настройка виджетов UI завершена.")

    def connect_signals(self):
        self.stateButton.clicked.connect(self.toggle_firewall_state_requested)
        self.addeditRuleButton.clicked.connect(self.add_new_rule_requested) # Отдельный слот для кнопки "Добавить"
        self.deleteRuleButton.clicked.connect(self.delete_rule_requested)
        self.listOfRules.itemSelectionChanged.connect(self.update_rule_buttons_state)
        self.listOfRules.itemDoubleClicked.connect(self.edit_selected_rule_requested) # Двойной клик для редактирования
        self.terminateConnectionButton.clicked.connect(self.terminate_connection_requested)
        self.listOfConnections.itemSelectionChanged.connect(self.update_connection_buttons_state)
        # Чекбоксы логирования
        for chk_box in [self.approvedPackets, self.prohibitedPackets, self.rejectedPackets,
                        self.tcpPackets, self.udpPackets, self.icmpPackets]:
            chk_box.toggled.connect(self.save_current_log_settings_requested) # Запускаем сохранение через воркер
        self.addIpButton.clicked.connect(self.add_unlogged_ip_requested)
        self.addPortButton.clicked.connect(self.add_unlogged_port_requested)
        self.removeIpButton.clicked.connect(self.remove_unlogged_ip_requested)
        self.removePortButton.clicked.connect(self.remove_unlogged_port_requested)
        self.chooseFolderButton.clicked.connect(self.choose_log_folder) # Это можно оставить синхронным
        print("Сигналы UI подключены.")

    def initialize_ui_state(self):
        print("Инициализация состояния UI...")
        self.request_firewall_status_update() # Запросит статус и обновит зависимые UI
        self.request_rules_update()
        self.request_connections_update()
        self.request_log_settings_update()
        # Кнопки обновятся после получения данных
        self.update_rule_buttons_state(False) # Изначально выключаем кнопки (нет выбора)
        self.update_connection_buttons_state(False)


    # --- Общие обработчики для воркеров ---
    @pyqtSlot(str)
    def handle_operation_error(self, error_message):
        QMessageBox.critical(self, "Ошибка операции", error_message)
        # Можно добавить обновление UI, чтобы отразить возможное несоответствие
        self.request_firewall_status_update() # Обновим статус на всякий случай
        self.request_rules_update()
        print(f"UI: Ошибка операции: {error_message}")

    @pyqtSlot(str)
    def handle_generic_success(self, message):
        # Для простых операций, где не нужно специфическое обновление UI кроме сообщения
        QMessageBox.information(self, "Успех", message)
        print(f"UI: Успешная операция: {message}")
        # Обновляем зависимые части UI
        if "правил" in message.lower() or "правило" in message.lower():
             self.request_rules_update()
        if "лог" in message.lower():
             self.request_log_settings_update() # Перезагружаем настройки логов
             self.request_recent_actions_update()


    # --- Статус фаервола ---
    def toggle_firewall_state_requested(self):
        self.stateButton.setEnabled(False)
        operation = "disable" if self.firewall_logic._is_enabled else "enable" # Используем _is_enabled для быстрого решения
        worker = self._start_worker("status_toggle", StatusWorker, self.firewall_logic, operation)
        if worker:
            worker.operation_successful.connect(self.handle_status_toggle_success)
            worker.error_occurred.connect(self.handle_operation_error)
            worker.finished.connect(lambda: self.stateButton.setEnabled(True))

    @pyqtSlot(str)
    def handle_status_toggle_success(self, message):
        QMessageBox.information(self, "Статус фаервола", message)
        self.request_firewall_status_update() # Запросить актуальный статус и обновить UI

    def request_firewall_status_update(self):
        worker = self._start_worker("status_get", StatusWorker, self.firewall_logic, "get")
        if worker:
            worker.status_ready.connect(self.update_firewall_status_ui_from_signal)
            worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(bool)
    def update_firewall_status_ui_from_signal(self, is_enabled):
        self.firewall_logic._is_enabled = is_enabled # Сохраняем локально
        if is_enabled:
            self.stateButton.setText("Выключить")
            self.firewallWork.setText("Работа фаервола: <font color='green'>Включен</font>")
        else:
            self.stateButton.setText("Включить")
            self.firewallWork.setText("Работа фаервола: <font color='red'>Выключен</font>")
        self.update_rule_buttons_state(is_enabled) # Передаем статус для блокировки кнопок
        self.update_connection_buttons_state(is_enabled)
        self.request_recent_actions_update()
        print(f"UI: Статус фаервола обновлен -> {'ВКЛ' if is_enabled else 'ВЫКЛ'}")

    # --- Правила ---
    def request_rules_update(self):
        worker = self._start_worker("rules_get", RulesWorker, self.firewall_logic, "get")
        if worker:
            worker.rules_ready.connect(self.display_rules_from_signal)
            worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(list)
    def display_rules_from_signal(self, rules):
        print(f"UI: Отображение {len(rules)} правил из сигнала")
        self.listOfRules.setRowCount(0)
        self.listOfRules.setRowCount(len(rules))
        can_edit_rules = self.firewall_logic.is_enabled_sync() # Для чекбоксов
        for row, rule_data in enumerate(rules):
            item_id = QTableWidgetItem(str(rule_data.get("id", ""))); item_id.setData(Qt.UserRole, rule_data.get("id"))
            widget_enabled = QWidget(); chk_enabled = QCheckBox(); chk_enabled.setChecked(rule_data.get("enabled", False))
            chk_enabled.setProperty("rule_id", rule_data.get("id")); chk_enabled.toggled.connect(self.toggle_rule_enabled_state_requested)
            chk_enabled.setEnabled(can_edit_rules) # Блокируем, если фаервол выключен
            layout = QVBoxLayout(widget_enabled); layout.addWidget(chk_enabled); layout.setAlignment(Qt.AlignCenter); layout.setContentsMargins(0,0,0,0)

            self.listOfRules.setItem(row, 0, item_id)
            self.listOfRules.setCellWidget(row, 1, widget_enabled)
            self.listOfRules.setItem(row, 2, QTableWidgetItem(rule_data.get("action", "")))
            self.listOfRules.setItem(row, 3, QTableWidgetItem(rule_data.get("proto", "")))
            self.listOfRules.setItem(row, 4, QTableWidgetItem(rule_data.get("src", "")))
            self.listOfRules.setItem(row, 5, QTableWidgetItem(str(rule_data.get("sport", ""))))
            self.listOfRules.setItem(row, 6, QTableWidgetItem(rule_data.get("dst", "")))
            self.listOfRules.setItem(row, 7, QTableWidgetItem(str(rule_data.get("dport", ""))))
            self.listOfRules.setItem(row, 8, QTableWidgetItem(rule_data.get("description", "")))
        self.update_rule_buttons_state()

    @pyqtSlot()
    def update_rule_buttons_state(self, firewall_enabled=None):
        if firewall_enabled is None: # Если не передано, берем из логики
             firewall_enabled = self.firewall_logic.is_enabled_sync()
        has_selection = len(self.listOfRules.selectedItems()) > 0
        self.deleteRuleButton.setEnabled(has_selection and firewall_enabled)
        self.addeditRuleButton.setEnabled(firewall_enabled) # Кнопку "Добавить" всегда активна, если фаервол вкл

    @pyqtSlot()
    def add_new_rule_requested(self):
        print("UI: Запрос на добавление нового правила")
        self._show_rule_dialog_worker() # Вызываем общий метод без данных

    @pyqtSlot(QTableWidgetItem)
    def edit_selected_rule_requested(self, item):
        print("UI: Запрос на редактирование правила (двойной клик)")
        selected_row = item.row()
        if selected_row >= 0:
            rule_id = self.listOfRules.item(selected_row, 0).data(Qt.UserRole)
            if rule_id is None: rule_id = int(self.listOfRules.item(selected_row, 0).text())
            # Находим правило в self.firewall_logic.defined_rules по ID (это надежнее)
            rule_data_to_edit = next((r for r in self.firewall_logic.defined_rules if r.get("id") == rule_id), None)
            if rule_data_to_edit:
                self._show_rule_dialog_worker(rule_data_to_edit.copy()) # Передаем КОПИЮ
            else:
                QMessageBox.warning(self, "Ошибка", f"Правило ID {rule_id} не найдено для редактирования.")

    def _show_rule_dialog_worker(self, rule_data=None):
        """ Показывает диалог и обрабатывает результат через воркер """
        dialog = AddEditRuleDialog(self, rule_data)
        if dialog.exec_() == QDialog.Accepted:
            new_or_edited_rule_data = dialog.get_data()
            if new_or_edited_rule_data:
                worker = self._start_worker("rule_add_edit", RulesWorker, self.firewall_logic, "add_edit", new_or_edited_rule_data)
                if worker:
                    worker.operation_successful.connect(self.handle_rule_operation_success_generic)
                    worker.error_occurred.connect(self.handle_operation_error)
        else:
            print("Добавление/редактирование правила отменено пользователем.")

    @pyqtSlot(str)
    def handle_rule_operation_success_generic(self, message): # Общий для add/edit/delete
        QMessageBox.information(self, "Успех", message)
        self.request_rules_update() # Обновляем таблицу

    def delete_rule_requested(self):
        selected_items = self.listOfRules.selectedItems()
        if not selected_items: QMessageBox.warning(self, "Ошибка", "Не выбрано правило."); return
        rule_id = self.listOfRules.item(selected_items[0].row(), 0).data(Qt.UserRole)
        if rule_id is None: rule_id = int(self.listOfRules.item(selected_items[0].row(), 0).text())

        reply = QMessageBox.question(self, 'Удаление', f"Удалить правило ID {rule_id}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            worker = self._start_worker(f"rule_delete_{rule_id}", RulesWorker, self.firewall_logic, "delete", rule_id)
            if worker:
                worker.operation_successful.connect(self.handle_rule_operation_success_generic)
                worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(bool)  # Слот для сигнала toggled от чекбокса правила
    def toggle_rule_enabled_state_requested(self):
        sender_checkbox = self.sender()  # Получаем сам QCheckBox
        if sender_checkbox and isinstance(sender_checkbox, QCheckBox):  # Добавим проверку типа
            rule_id = sender_checkbox.property("rule_id")
            is_enabled_new_state = sender_checkbox.isChecked()  # Новое желаемое состояние

            if rule_id is None:
                print("Ошибка: Не удалось получить rule_id из чекбокса.")
                # Возможно, откатить состояние чекбокса обратно, если оно изменилось
                sender_checkbox.setChecked(not is_enabled_new_state)
                return

            print(f"UI: Запрос на изменение состояния правила ID {rule_id} на {is_enabled_new_state}")
            sender_checkbox.setEnabled(False)  # Блокируем чекбокс на время операции

            # Данные для воркера
            data_for_worker = {"rule_id": rule_id, "is_enabled": is_enabled_new_state}

            # Имя воркера (можно сделать более уникальным, если нужно)
            worker_name = f"rule_toggle_{rule_id}"

            # Используем _start_worker для создания и запуска
            self.rule_toggle_op_worker = self._start_worker(
                worker_name,
                RulesWorker,  # Класс воркера
                self.firewall_logic,  # Аргумент для __init__ RulesWorker
                "toggle_enabled",  # operation
                data_for_worker  # data
            )

            if self.rule_toggle_op_worker:
                # Передаем ссылку на чекбокс через functools.partial в обработчики
                success_slot_with_checkbox = functools.partial(self.handle_rule_toggle_success,
                                                               checkbox=sender_checkbox)
                error_slot_with_checkbox = functools.partial(self.handle_rule_toggle_error_and_revert_checkbox,
                                                             checkbox=sender_checkbox)

                self.rule_toggle_op_worker.operation_successful.connect(success_slot_with_checkbox)
                self.rule_toggle_op_worker.error_occurred.connect(error_slot_with_checkbox)
                # finished и deleteLater уже обрабатываются в _start_worker
            else:
                # Если воркер не запустился (например, уже есть активный с таким именем)
                # нужно разблокировать чекбокс
                sender_checkbox.setEnabled(True)
                print(f"Не удалось запустить воркер {worker_name} для toggle_rule_enabled_state.")
        else:
            print("Ошибка: sender() не является QCheckBox в toggle_rule_enabled_state_requested")

    @pyqtSlot(str, QCheckBox)  # Убедись, что QCheckBox здесь указан
    def handle_rule_toggle_success(self, message, checkbox):
        QMessageBox.information(self, "Состояние правила", message)
        if checkbox:
            checkbox.setEnabled(True)  # Разблокируем переданный чекбокс
        # Обновляем всю таблицу, чтобы состояние точно соответствовало бэкенду
        self.request_rules_update()
        print(f"UI: Успешное изменение состояния правила, чекбокс: {checkbox.objectName() if checkbox else 'None'}")

    @pyqtSlot(str, QCheckBox)  # Убедись, что QCheckBox здесь указан
    def handle_rule_toggle_error_and_revert_checkbox(self, error_message, checkbox):
        QMessageBox.critical(self, "Ошибка изменения состояния", error_message)
        if checkbox:
            # Важно: откатываем состояние чекбокса к тому, каким оно было ДО попытки изменения,
            # а не просто инвертируем текущее. Для этого нужно знать предыдущее состояние,
            # либо просто перезагрузить правила, чтобы UI синхронизировался с бэкендом,
            # который не должен был изменить состояние правила в defined_rules при ошибке.
            print(
                f"UI: Ошибка изменения состояния правила, чекбокс: {checkbox.objectName() if checkbox else 'None'}. Откат не реализован, перезагружаем правила.")
            checkbox.setEnabled(True)  # Разблокируем в любом случае
        # Перезагружаем правила, чтобы UI отобразил актуальное состояние из FirewallLogic
        self.request_rules_update()

    # --- Соединения ---
    def request_connections_update(self):
        worker = self._start_worker("connections_get", ConnectionWorker, self.firewall_logic, "get")
        if worker:
            worker.connections_ready.connect(self.display_connections_from_signal)
            worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(list)
    def display_connections_from_signal(self, connections):
        print(f"UI: Отображение {len(connections)} соединений")
        self.listOfConnections.setRowCount(0)
        self.listOfConnections.setRowCount(len(connections))
        for row, conn in enumerate(connections):
            self.listOfConnections.setItem(row, 0, QTableWidgetItem(conn.get("local", "")))
            self.listOfConnections.setItem(row, 1, QTableWidgetItem(conn.get("remote", "")))
            self.listOfConnections.setItem(row, 2, QTableWidgetItem(conn.get("proto", "")))
            self.listOfConnections.setItem(row, 3, QTableWidgetItem(conn.get("state", "")))
        self.update_connection_buttons_state()

    @pyqtSlot()
    def update_connection_buttons_state(self, firewall_enabled=None):
        if firewall_enabled is None: firewall_enabled = self.firewall_logic.is_enabled_sync()
        has_selection = len(self.listOfConnections.selectedItems()) > 0
        self.terminateConnectionButton.setEnabled(has_selection and firewall_enabled)

    def terminate_connection_requested(self):
        selected_items = self.listOfConnections.selectedItems()
        if not selected_items: QMessageBox.warning(self, "Ошибка", "Не выбрано соединение."); return
        row = selected_items[0].row()
        conn_data = {"local": self.listOfConnections.item(row,0).text(), "remote": self.listOfConnections.item(row,1).text(),
                     "proto": self.listOfConnections.item(row,2).text(), "state": self.listOfConnections.item(row,3).text()}
        reply = QMessageBox.question(self, 'Разрыв', f"Разорвать: {conn_data['local']} <-> {conn_data['remote']}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            worker = self._start_worker("conn_terminate", ConnectionWorker, self.firewall_logic, "terminate", conn_data)
            if worker:
                worker.operation_successful.connect(self.handle_connection_terminated_success)
                worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(str)
    def handle_connection_terminated_success(self, message):
        QMessageBox.information(self, "Соединение", message)
        self.request_connections_update() # Обновляем список

    # --- Логи ---
    def request_recent_actions_update(self):
        worker = self._start_worker("logs_recent", LogWorker, self.firewall_logic, "get_recent")
        if worker:
            worker.recent_actions_ready.connect(self.display_recent_actions_from_signal)
            worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(list)
    def display_recent_actions_from_signal(self, actions):
        self.recentActionsListWidget.clear()
        self.recentActionsListWidget.addItems(actions)
        print(f"UI: Отображено {len(actions)} последних действий.")

    def request_log_settings_update(self):
        worker = self._start_worker("logs_settings_get", LogWorker, self.firewall_logic, "get_settings")
        if worker:
            worker.log_settings_ready.connect(self.display_log_settings_from_signal)
            worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(dict)
    def display_log_settings_from_signal(self, settings):
        print("UI: Отображение настроек логирования")
        for chk, key in [(self.approvedPackets, "log_approved"), (self.prohibitedPackets, "log_prohibited"),
                         (self.rejectedPackets, "log_rejected"), (self.tcpPackets, "log_tcp"),
                         (self.udpPackets, "log_udp"), (self.icmpPackets, "log_icmp")]:
            chk.blockSignals(True); chk.setChecked(settings.get(key, False)); chk.blockSignals(False)

        self.unloggedIPListWidget.clear(); self.unloggedIPListWidget.addItems(settings.get("unlogged_ips", [])); self.unloggedIPListWidget.sortItems()
        self.unloggedPortListWidget.clear(); self.unloggedPortListWidget.addItems([str(p) for p in settings.get("unlogged_ports", [])])
        all_ports = [self.unloggedPortListWidget.item(i).text() for i in range(self.unloggedPortListWidget.count())]
        self.unloggedPortListWidget.clear(); self.unloggedPortListWidget.addItems(sorted(all_ports, key=int))


        self.log_folder_path = settings.get("log_folder", "/var/log/myfirewall")
        if hasattr(self, 'logFolderPathLabel'): self.logFolderPathLabel.setText(f"Папка логов: {self.log_folder_path}")

    @pyqtSlot() # Слот для сигнала toggled от чекбоксов настроек логов
    def save_current_log_settings_requested(self):
        print("UI: Запрос на сохранение настроек логирования")
        # Собираем текущие настройки из UI
        settings = {
            "log_approved": self.approvedPackets.isChecked(), "log_prohibited": self.prohibitedPackets.isChecked(),
            "log_rejected": self.rejectedPackets.isChecked(), "log_tcp": self.tcpPackets.isChecked(),
            "log_udp": self.udpPackets.isChecked(), "log_icmp": self.icmpPackets.isChecked(),
            "unlogged_ips": [self.unloggedIPListWidget.item(i).text() for i in range(self.unloggedIPListWidget.count())],
            "unlogged_ports": [int(p.text()) for p in [self.unloggedPortListWidget.item(i) for i in range(self.unloggedPortListWidget.count())] if p.text().isdigit()],
            "log_folder": self.log_folder_path
        }
        worker = self._start_worker("logs_settings_update", LogWorker, self.firewall_logic, "update_settings", settings)
        if worker:
            worker.operation_successful.connect(self.handle_generic_success)
            worker.error_occurred.connect(self.handle_operation_error)

    def add_unlogged_ip_requested(self):
        ip = self.lineEdit.text().strip()
        if not ip: QMessageBox.warning(self, "Внимание", "Введите IP."); return
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip): QMessageBox.warning(self, "Ошибка", "Неверный IP."); return
        # Проверка на дубликат
        if self.unloggedIPListWidget.findItems(ip, Qt.MatchExactly):
            QMessageBox.information(self, "Инфо", f"IP {ip} уже в списке."); return

        worker = self._start_worker(f"log_add_ip_{ip}", LogWorker, self.firewall_logic, "add_ip", ip)
        if worker:
            worker.operation_successful.connect(self.handle_log_list_change_success)
            worker.error_occurred.connect(self.handle_operation_error)

    def add_unlogged_port_requested(self):
        port_s = self.lineEdit_2.text().strip()
        if not port_s: QMessageBox.warning(self, "Внимание", "Введите порт."); return
        try: port_i = int(port_s); assert 0 <= port_i <= 65535
        except (ValueError, AssertionError): QMessageBox.warning(self, "Ошибка", "Неверный порт."); return
        if self.unloggedPortListWidget.findItems(port_s, Qt.MatchExactly):
            QMessageBox.information(self, "Инфо", f"Порт {port_s} уже в списке."); return

        worker = self._start_worker(f"log_add_port_{port_i}", LogWorker, self.firewall_logic, "add_port", port_i)
        if worker:
            worker.operation_successful.connect(self.handle_log_list_change_success)
            worker.error_occurred.connect(self.handle_operation_error)

    def remove_unlogged_ip_requested(self):
        item = self.unloggedIPListWidget.currentItem()
        if not item: QMessageBox.warning(self, "Внимание", "Выберите IP."); return
        ip = item.text()
        reply = QMessageBox.question(self, "Удаление", f"Удалить IP {ip} из нелоггируемых?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            worker = self._start_worker(f"log_remove_ip_{ip}", LogWorker, self.firewall_logic, "remove_ip", ip)
            if worker:
                worker.operation_successful.connect(self.handle_log_list_change_success)
                worker.error_occurred.connect(self.handle_operation_error)

    def remove_unlogged_port_requested(self):
        item = self.unloggedPortListWidget.currentItem()
        if not item: QMessageBox.warning(self, "Внимание", "Выберите порт."); return
        port_s = item.text()
        reply = QMessageBox.question(self, "Удаление", f"Удалить порт {port_s} из нелоггируемых?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            worker = self._start_worker(f"log_remove_port_{port_s}", LogWorker, self.firewall_logic, "remove_port", port_s)
            if worker:
                worker.operation_successful.connect(self.handle_log_list_change_success)
                worker.error_occurred.connect(self.handle_operation_error)

    @pyqtSlot(str)
    def handle_log_list_change_success(self, message):
        QMessageBox.information(self, "Настройки логов", message)
        self.lineEdit.clear(); self.lineEdit_2.clear() # Очищаем поля ввода
        self.request_log_settings_update() # Обновляем все списки и чекбоксы

    def choose_log_folder(self): # Можно оставить синхронным
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для логов", self.log_folder_path)
        if folder:
            self.log_folder_path = folder
            if hasattr(self, 'logFolderPathLabel'): self.logFolderPathLabel.setText(f"Папка логов: {self.log_folder_path}")
            self.save_current_log_settings_requested() # Сохраняем через воркер

    def closeEvent(self, event):
        """ Обработка события закрытия окна для корректного завершения """
        # Здесь можно добавить ожидание завершения активных воркеров, если нужно
        # Например, показать диалог "Пожалуйста, подождите..."
        # Но для простоты пока просто принимаем закрытие
        print("Приложение закрывается.")
        # Можно добавить сохранение каких-либо настроек перед выходом,
        # но основные (правила, логи) уже должны сохраняться по ходу работы.
        event.accept()

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
# --- END OF FILE firewall_app_v4_release.py ---