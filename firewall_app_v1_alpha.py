import sys
import json
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton, QLabel, QListView,
    QTableWidget, QTabWidget, QCheckBox, QLineEdit, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QMessageBox, QFileDialog, QVBoxLayout
)
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, Qt

# Placeholder для будущей логики фаервола
# В реальном приложении здесь будет класс, взаимодействующий
# с iptables/nftables, потоками и т.д.
class FirewallLogic:
    def __init__(self):
        self._is_enabled = False # Пример внутреннего состояния
        self.firewall_rules = {}
        self.firewall_logging_settings = {}
        self.firewall_ips = {}

    def is_enabled(self):
        # TODO: Получить реальный статус фаервола из системы
        print("Backend: Checking firewall status...")
        return self._is_enabled

    def enable_firewall(self):
        # TODO: Реализовать включение фаервола (iptables/nftables)
        print("Backend: Enabling firewall...")
        self._is_enabled = True
        return True # Успех

    def disable_firewall(self):
        # TODO: Реализовать выключение фаервола (iptables/nftables)
        print("Backend: Disabling firewall...")
        self._is_enabled = False
        return True # Успех

    def get_rules(self):
        # TODO: Получить список правил из iptables/nftables
        print("Backend: Getting rules...")
        # Пример данных
        return [
            {"id": 1, "enabled": True, "action": "ACCEPT", "proto": "TCP", "src": "any", "sport": "any", "dst": "any", "dport": "80"},
            {"id": 2, "enabled": True, "action": "ACCEPT", "proto": "TCP", "src": "any", "sport": "any", "dst": "any", "dport": "22"},
            {"id": 3, "enabled": False, "action": "DROP", "proto": "ICMP", "src": "192.168.1.100", "sport": "any", "dst": "any", "dport": "any"},
        ]

    def delete_rule(self, rule_id):
        # TODO: Реализовать удаление правила по ID (или номеру строки)
        print(f"Backend: Deleting rule with ID: {rule_id}")
        return True # Успех

    def add_edit_rule(self, rule_data):
         # TODO: Реализовать добавление/редактирование правила
        if rule_data.get("id"):
            print(f"Backend: Editing rule: {rule_data}")
        else:
            print(f"Backend: Adding new rule: {rule_data}")
        return True # Успех

    def get_connections(self):
        # TODO: Получить список активных соединений (conntrack/nft)
        print("Backend: Getting connections...")
        # Пример данных
        return [
            {"local": "192.168.1.5:54321", "remote": "8.8.8.8:53", "proto": "UDP", "state": "ESTABLISHED"},
            {"local": "192.168.1.5:12345", "remote": "1.1.1.1:443", "proto": "TCP", "state": "ESTABLISHED"},
        ]

    def terminate_connection(self, connection_data):
        # TODO: Реализовать разрыв соединения
        print(f"Backend: Terminating connection: {connection_data}")
        return True # Успех

    def get_log_settings(self):
        # TODO: Получить текущие настройки логирования
        print("Backend: Getting log settings...")
        return {
            "log_approved": True, "log_prohibited": True, "log_rejected": False,
            "log_tcp": True, "log_udp": True, "log_icmp": True,
            "unlogged_ips": ["127.0.0.1"], "unlogged_ports": ["123"],
            "log_folder": "/var/log/myfirewall"
        }

    def update_log_settings(self, settings):
        # TODO: Сохранить настройки логирования
        print(f"Backend: Updating log settings: {settings}")
        return True

    def get_recent_actions(self):
         # TODO: Получить список последних действий из логов
         print("Backend: Getting recent actions...")
         return ["Firewall started", "Rule #2 modified", "Blocked connection from 10.0.0.1"]

    def add_unlogged_ip(self, ip):
        # TODO: Добавить IP в список нелоггируемых
        print(f"Backend: Adding unlogged IP: {ip}")
        return True

    def add_unlogged_port(self, port):
         # TODO: Добавить порт в список нелоггируемых
        print(f"Backend: Adding unlogged port: {port}")
        return True
# --- Конец placeholder'а ---

class MainWindow(QMainWindow):
    def __init__(self):
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

        # Создаем экземпляр логики (в реальном приложении он может передаваться извне)
        self.firewall_logic = FirewallLogic()

        # --- Настройка виджетов ---
        self.setup_widgets()

        # --- Подключение сигналов к слотам ---
        self.connect_signals()

        # --- Инициализация начального состояния ---
        self.initialize_ui_state()

    def setup_widgets(self):
        # Настройка таблицы правил
        self.listOfRules.setColumnCount(9) # Добавляем столбец для действий
        self.listOfRules.setHorizontalHeaderLabels(
            ["Номер", "Вкл/Выкл", "Действие", "Протокол", "Источник", "Порт ист.", "Назначение", "Порт назн.", "Описание"]
        )
        # Растягиваем последний столбец (Описание)
        self.listOfRules.horizontalHeader().setStretchLastSection(True)
        # Запрещаем редактирование ячеек напрямую
        self.listOfRules.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # Включаем выделение всей строки
        self.listOfRules.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfRules.setSelectionMode(QAbstractItemView.SingleSelection) # Только одну строку можно выбрать
        # Настройка ширины столбцов (пример)
        self.listOfRules.setColumnWidth(0, 50) # Номер
        self.listOfRules.setColumnWidth(1, 60) # Вкл/Выкл
        self.listOfRules.setColumnWidth(2, 80) # Действие
        self.listOfRules.setColumnWidth(3, 70) # Протокол

        # Настройка таблицы подключений
        self.listOfConnections.setColumnCount(4)
        self.listOfConnections.setHorizontalHeaderLabels(
             ["Локальный IP:Порт", "Удаленный IP:Порт", "Протокол", "Состояние"]
        )
        self.listOfConnections.horizontalHeader().setStretchLastSection(True)
        self.listOfConnections.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listOfConnections.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.listOfConnections.setSelectionMode(QAbstractItemView.SingleSelection)

        # Настройка списков на вкладке Логи (просто для примера, можно использовать QListWidget)
        # В UI у тебя QListView, для него нужна модель данных. QListWidget проще для старта.
        # Пока оставим QListView, но для наполнения нужна будет модель.

    def connect_signals(self):
        # --- Вкладка "Общее" ---
        self.stateButton.clicked.connect(self.toggle_firewall_state)

        # --- Вкладка "Правила" ---
        self.addeditRuleButton.clicked.connect(self.open_add_edit_rule_dialog)
        self.deleteRuleButton.clicked.connect(self.delete_selected_rule)
        self.listOfRules.itemSelectionChanged.connect(self.update_rule_buttons_state)
        # Двойной клик по строке для редактирования
        self.listOfRules.itemDoubleClicked.connect(self.open_add_edit_rule_dialog_for_selected)


        # --- Вкладка "Подключения" ---
        self.terminateConnectionButton.clicked.connect(self.terminate_selected_connection)
        self.listOfConnections.itemSelectionChanged.connect(self.update_connection_buttons_state)

        # --- Вкладка "Логи" ---
        # Группа чекбоксов для настроек логирования
        self.approvedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.prohibitedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.rejectedPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.tcpPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.udpPackets.toggled.connect(self.update_logging_config_from_checkbox)
        self.icmpPackets.toggled.connect(self.update_logging_config_from_checkbox)

        self.addIpButton.clicked.connect(self.add_unlogged_ip)
        self.addPortButton.clicked.connect(self.add_unlogged_port)
        self.chooseFolderButton.clicked.connect(self.choose_log_folder)

    def initialize_ui_state(self):
        # Устанавливаем начальное состояние кнопки и метки статуса фаервола
        self.update_firewall_status_ui()
        # Загружаем и отображаем правила
        self.load_and_display_rules()
        # Загружаем и отображаем соединения
        self.load_and_display_connections()
         # Загружаем и отображаем настройки логов
        self.load_and_display_log_settings()
        # Загружаем и отображаем последние действия
        self.load_and_display_recent_actions()
        # Обновляем состояние кнопок правил и соединений
        self.update_rule_buttons_state()
        self.update_connection_buttons_state()

    # --- Слоты для обработки сигналов ---

    # --- Вкладка "Общее" ---
    @pyqtSlot()
    def toggle_firewall_state(self):
        print("Сигнал: toggle_firewall_state сработал")
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
        self.update_firewall_status_ui()

    def update_firewall_status_ui(self):
        if self.firewall_logic.is_enabled():
            self.stateButton.setText("Выключить")
            # Можно добавить стили для цвета кнопки
            # self.stateButton.setStyleSheet("background-color: lightcoral;")
            # self.firewallWork.setText("Работа фаервола: <font color='green'>Включен</font>") # Пример с HTML
            print("UI Обновлен: Фаервол ВКЛ")
        else:
            self.stateButton.setText("Включить")
            # self.stateButton.setStyleSheet("") # Сброс стиля
            # self.firewallWork.setText("Работа фаервола: <font color='red'>Выключен</font>")
            print("UI Обновлен: Фаервол ВЫКЛ")
        # TODO: Обновить listView_3 (последние действия)
        self.load_and_display_recent_actions()


    def load_and_display_recent_actions(self):
         print("Загрузка последних действий...")
         actions = self.firewall_logic.get_recent_actions()
         # TODO: Отобразить 'actions' в self.listView_3
         # Для QListView нужна модель (QStringListModel или своя).
         # Пока просто выведем в консоль.
         print("Последние действия:", actions)


    # --- Вкладка "Правила" ---
    @pyqtSlot()
    def open_add_edit_rule_dialog(self, rule_data=None):
        print("Сигнал: open_add_edit_rule_dialog сработал")
        # TODO: Открыть новое окно/диалог для добавления/редактирования правила.
        # Если rule_data не None, значит это редактирование, передаем данные в диалог.
        # После сохранения в диалоге, он должен вызвать метод бэкэнда
        # и обновить таблицу правил здесь (self.load_and_display_rules).
        if rule_data:
            print(f"Редактирование правила: {rule_data}")
        else:
            print("Добавление нового правила")
        QMessageBox.information(self, "Функционал", "Окно добавления/редактирования правил еще не реализовано.")
        # После успешного добавления/редактирования нужно обновить таблицу:
        # self.load_and_display_rules()


    @pyqtSlot(QTableWidgetItem)
    def open_add_edit_rule_dialog_for_selected(self, item):
         print("Сигнал: Двойной клик по строке правила")
         selected_row = item.row()
         if selected_row >= 0:
             rule_id = self.listOfRules.item(selected_row, 0).data(Qt.UserRole) # Получаем ID из UserRole
             # TODO: Получить полные данные правила по ID из бэкенда
             rule_data = {"id": rule_id, "comment": "Пример данных для редактирования"} # Заглушка
             self.open_add_edit_rule_dialog(rule_data)


    @pyqtSlot()
    def delete_selected_rule(self):
        print("Сигнал: delete_selected_rule сработал")
        selected_items = self.listOfRules.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано правило для удаления.")
            return

        selected_row = selected_items[0].row()
        rule_id_item = self.listOfRules.item(selected_row, 0)

        if rule_id_item:
            # Используем Qt.UserRole для хранения реального ID правила, если номер строки не совпадает с ID
            rule_id = rule_id_item.data(Qt.UserRole)
            if rule_id is None: # Если ID не хранится, пробуем взять текст ячейки
                 try:
                    rule_id = int(rule_id_item.text())
                 except ValueError:
                     QMessageBox.critical(self, "Ошибка", "Не удалось определить ID правила.")
                     return

            reply = QMessageBox.question(self, 'Подтверждение',
                                         f"Вы уверены, что хотите удалить правило ID {rule_id}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                if self.firewall_logic.delete_rule(rule_id):
                    print(f"Правило ID {rule_id} удалено")
                    self.load_and_display_rules() # Обновляем таблицу
                else:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить правило ID {rule_id}.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось получить ID правила из выбранной строки.")


    @pyqtSlot()
    def update_rule_buttons_state(self):
        # Включаем/выключаем кнопки в зависимости от того, выбрана ли строка
        has_selection = len(self.listOfRules.selectedItems()) > 0
        self.deleteRuleButton.setEnabled(has_selection)
        # Кнопку редактирования можно активировать так же или обрабатывать двойной клик
        # self.addeditRuleButton.setEnabled(has_selection) # Если кнопка должна работать и для редактирования

    def load_and_display_rules(self):
        print("Загрузка и отображение правил...")
        rules = self.firewall_logic.get_rules()
        self.listOfRules.setRowCount(len(rules)) # Устанавливаем количество строк

        for row_index, rule in enumerate(rules):
            # Создаем элементы для каждой ячейки
            item_id = QTableWidgetItem(str(rule.get("id", "")))
            # Сохраняем реальный ID правила в UserRole, если он отличается от номера строки
            item_id.setData(Qt.UserRole, rule.get("id"))

            # Чекбокс для Вкл/Выкл
            item_enabled_widget = QWidget()
            chk_enabled = QCheckBox()
            chk_enabled.setChecked(rule.get("enabled", False))
            chk_enabled.setProperty("rule_id", rule.get("id")) # Сохраняем ID для обработчика
            chk_enabled.toggled.connect(self.toggle_rule_enabled_state)
            layout = QVBoxLayout(item_enabled_widget)
            layout.addWidget(chk_enabled)
            layout.setAlignment(Qt.AlignCenter)
            layout.setContentsMargins(0,0,0,0)
            item_enabled_widget.setLayout(layout)


            item_action = QTableWidgetItem(rule.get("action", ""))
            item_proto = QTableWidgetItem(rule.get("proto", ""))
            item_src = QTableWidgetItem(rule.get("src", ""))
            item_sport = QTableWidgetItem(rule.get("sport", ""))
            item_dst = QTableWidgetItem(rule.get("dst", "")) # !!! В UI названо "Порт", исправил на "Назначение" в коде
            item_dport = QTableWidgetItem(rule.get("dport", ""))
            item_desc = QTableWidgetItem(rule.get("description", "")) # Добавил столбец для описания

            # Устанавливаем элементы в таблицу
            self.listOfRules.setItem(row_index, 0, item_id)
            self.listOfRules.setCellWidget(row_index, 1, item_enabled_widget) # Используем setCellWidget для чекбокса
            self.listOfRules.setItem(row_index, 2, item_action)
            self.listOfRules.setItem(row_index, 3, item_proto)
            self.listOfRules.setItem(row_index, 4, item_src)
            self.listOfRules.setItem(row_index, 5, item_sport)
            self.listOfRules.setItem(row_index, 6, item_dst) # Назначение
            self.listOfRules.setItem(row_index, 7, item_dport)
            self.listOfRules.setItem(row_index, 8, item_desc) # Описание

        self.update_rule_buttons_state() # Обновляем состояние кнопок после загрузки

    @pyqtSlot(bool)
    def toggle_rule_enabled_state(self):
         sender_checkbox = self.sender() # Получаем чекбокс, который отправил сигнал
         if sender_checkbox:
             rule_id = sender_checkbox.property("rule_id")
             is_enabled = sender_checkbox.isChecked()
             print(f"Сигнал: toggle_rule_enabled_state для правила ID {rule_id}, новое состояние: {is_enabled}")
             # TODO: Вызвать метод бэкэнда для изменения состояния правила
             # if not self.firewall_logic.set_rule_enabled(rule_id, is_enabled):
             #     QMessageBox.warning(self, "Ошибка", f"Не удалось изменить состояние правила ID {rule_id}")
             #     sender_checkbox.setChecked(not is_enabled) # Вернуть чекбокс в прежнее состояние


    # --- Вкладка "Подключения" ---
    @pyqtSlot()
    def terminate_selected_connection(self):
        print("Сигнал: terminate_selected_connection сработал")
        selected_items = self.listOfConnections.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Ошибка", "Не выбрано соединение для разрыва.")
            return

        selected_row = selected_items[0].row()
        # Собираем данные о соединении из строки таблицы
        try:
            connection_data = {
                "local": self.listOfConnections.item(selected_row, 0).text(),
                "remote": self.listOfConnections.item(selected_row, 1).text(),
                "proto": self.listOfConnections.item(selected_row, 2).text(),
                "state": self.listOfConnections.item(selected_row, 3).text(),
            }
        except AttributeError: # Если ячейка пустая
             QMessageBox.critical(self, "Ошибка", "Не удалось получить данные соединения из выбранной строки.")
             return


        reply = QMessageBox.question(self, 'Подтверждение',
                                     f"Вы уверены, что хотите разорвать соединение:\n{connection_data['local']} <-> {connection_data['remote']}?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            if self.firewall_logic.terminate_connection(connection_data):
                 print(f"Соединение разорвано: {connection_data}")
                 self.load_and_display_connections() # Обновляем таблицу
            else:
                 QMessageBox.critical(self, "Ошибка", f"Не удалось разорвать соединение.")


    @pyqtSlot()
    def update_connection_buttons_state(self):
        # Включаем/выключаем кнопку в зависимости от того, выбрана ли строка
        has_selection = len(self.listOfConnections.selectedItems()) > 0
        self.terminateConnectionButton.setEnabled(has_selection)

    def load_and_display_connections(self):
        print("Загрузка и отображение соединений...")
        connections = self.firewall_logic.get_connections()
        self.listOfConnections.setRowCount(len(connections)) # Устанавливаем количество строк

        for row_index, conn in enumerate(connections):
            # Создаем элементы для каждой ячейки
            item_local = QTableWidgetItem(conn.get("local", ""))
            item_remote = QTableWidgetItem(conn.get("remote", ""))
            item_proto = QTableWidgetItem(conn.get("proto", ""))
            item_state = QTableWidgetItem(conn.get("state", ""))

            # Устанавливаем элементы в таблицу
            self.listOfConnections.setItem(row_index, 0, item_local)
            self.listOfConnections.setItem(row_index, 1, item_remote)
            self.listOfConnections.setItem(row_index, 2, item_proto)
            self.listOfConnections.setItem(row_index, 3, item_state)

        self.update_connection_buttons_state() # Обновляем состояние кнопки

    # --- Вкладка "Логи" ---
    @pyqtSlot(bool)
    def update_logging_config_from_checkbox(self, checked):
         # Этот слот вызывается при изменении ЛЮБОГО чекбокса настроек
         print(f"Сигнал: update_logging_config_from_checkbox, состояние: {checked}")
         self.save_current_log_settings()

    def save_current_log_settings(self):
         settings = {
            "log_approved": self.approvedPackets.isChecked(),
            "log_prohibited": self.prohibitedPackets.isChecked(),
            "log_rejected": self.rejectedPackets.isChecked(),
            "log_tcp": self.tcpPackets.isChecked(),
            "log_udp": self.udpPackets.isChecked(),
            "log_icmp": self.icmpPackets.isChecked(),
            # TODO: Получить списки нелоггируемых IP и портов из QListView
            "unlogged_ips": [], # Заглушка
            "unlogged_ports": [], # Заглушка
            # TODO: Получить путь к папке логов (если он где-то хранится в UI)
            "log_folder": "" # Заглушка
         }
         if not self.firewall_logic.update_log_settings(settings):
              QMessageBox.warning(self, "Ошибка", "Не удалось сохранить настройки логирования.")
         else:
              print("Настройки логирования сохранены")

    def load_and_display_log_settings(self):
        print("Загрузка и отображение настроек логов...")
        settings = self.firewall_logic.get_log_settings()

        # Блокируем сигналы на время установки состояния, чтобы не вызвать save_current_log_settings
        self.approvedPackets.blockSignals(True)
        self.prohibitedPackets.blockSignals(True)
        self.rejectedPackets.blockSignals(True)
        self.tcpPackets.blockSignals(True)
        self.udpPackets.blockSignals(True)
        self.icmpPackets.blockSignals(True)

        self.approvedPackets.setChecked(settings.get("log_approved", False))
        self.prohibitedPackets.setChecked(settings.get("log_prohibited", False))
        self.rejectedPackets.setChecked(settings.get("log_rejected", False))
        self.tcpPackets.setChecked(settings.get("log_tcp", False))
        self.udpPackets.setChecked(settings.get("log_udp", False))
        self.icmpPackets.setChecked(settings.get("log_icmp", False))

        # Разблокируем сигналы
        self.approvedPackets.blockSignals(False)
        self.prohibitedPackets.blockSignals(False)
        self.rejectedPackets.blockSignals(False)
        self.tcpPackets.blockSignals(False)
        self.udpPackets.blockSignals(False)
        self.icmpPackets.blockSignals(False)

        # TODO: Отобразить списки нелоггируемых IP и портов в self.listView и self.listView_2
        print("Нелоггируемые IP:", settings.get("unlogged_ips", []))
        print("Нелоггируемые порты:", settings.get("unlogged_ports", []))
        # TODO: Отобразить путь к папке логов (возможно, в QLabel рядом с кнопкой)
        print("Папка логов:", settings.get("log_folder", ""))


    @pyqtSlot()
    def add_unlogged_ip(self):
        print("Сигнал: add_unlogged_ip сработал")
        ip_address = self.lineEdit.text().strip()
        if not ip_address:
             QMessageBox.warning(self, "Внимание", "Введите IP-адрес.")
             return
        # TODO: Добавить валидацию IP-адреса
        if self.firewall_logic.add_unlogged_ip(ip_address):
            print(f"Добавлен IP: {ip_address}")
            self.lineEdit.clear()
            self.load_and_display_log_settings() # Обновляем список в UI
        else:
             QMessageBox.warning(self, "Ошибка", f"Не удалось добавить IP-адрес {ip_address}.")


    @pyqtSlot()
    def add_unlogged_port(self):
        print("Сигнал: add_unlogged_port сработал")
        port_str = self.lineEdit_2.text().strip()
        if not port_str:
             QMessageBox.warning(self, "Внимание", "Введите номер порта.")
             return
        # TODO: Добавить валидацию порта (число, диапазон 0-65535)
        try:
            port = int(port_str)
            if not 0 <= port <= 65535:
                 raise ValueError("Порт вне допустимого диапазона")
        except ValueError as e:
             QMessageBox.warning(self, "Ошибка", f"Некорректный номер порта: {e}")
             return

        if self.firewall_logic.add_unlogged_port(port):
             print(f"Добавлен порт: {port}")
             self.lineEdit_2.clear()
             self.load_and_display_log_settings() # Обновляем список в UI
        else:
             QMessageBox.warning(self, "Ошибка", f"Не удалось добавить порт {port}.")


    @pyqtSlot()
    def choose_log_folder(self):
        print("Сигнал: choose_log_folder сработал")
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку для логов", ".") # Начинаем с текущей папки
        if folder_path:
            print(f"Выбрана папка: {folder_path}")
            # TODO: Сохранить путь к папке в настройках
            # settings = self.firewall_logic.get_log_settings()
            # settings["log_folder"] = folder_path
            # self.firewall_logic.update_log_settings(settings)
            # self.load_and_display_log_settings() # Обновить UI

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())