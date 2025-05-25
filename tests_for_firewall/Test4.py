# scapy_test_udp.py
from scapy.all import IP, UDP, ICMP, sr1, conf, RandShort
import sys

# --- НАСТРОЙКИ ---
VM_IP = "10.211.55.13"
TARGET_PORT = 53 # Пример: DNS порт (часто UDP). Убедись, что на VM что-то слушает этот UDP порт, если ожидаешь ответ.
# TARGET_PORT = 12345 # Или порт, который должен быть закрыт
# conf.iface = "en0"
TIMEOUT_SECONDS = 3
# --- КОНЕЦ НАСТРОЕК ---

print(f"--- Тест UDP порта {TARGET_PORT} на {VM_IP} ---")

try:
    ip_layer = IP(dst=VM_IP)
    udp_layer = UDP(dport=TARGET_PORT, sport=RandShort()) # Случайный порт источника
    packet = ip_layer/udp_layer/"TestPayload" # Добавляем небольшую нагрузку

    print(f"Отправка UDP пакета на {VM_IP}:{TARGET_PORT}...")
    # Для UDP мы можем ожидать ICMP Port Unreachable, если порт закрыт,
    # или ответ от приложения, если порт открыт, или ничего (если заблокировано DROP).
    reply = sr1(packet, timeout=TIMEOUT_SECONDS, verbose=0)

    if reply:
        print(f"Получен ответ от {reply.src}:")
        reply.show()
        if reply.haslayer(ICMP):
            if reply[ICMP].type == 3 and reply[ICMP].code == 3: # Destination Unreachable, Port Unreachable
                print(f"[УСПЕХ ТЕСТА/ИНФО] Получен ICMP Port Unreachable. Порт UDP {TARGET_PORT} вероятнее всего ЗАКРЫТ на уровне ОС/сервиса.")
            else:
                print(f"[ИНФО] Получен другой тип ICMP: type={reply[ICMP].type}, code={reply[ICMP].code}")
        elif reply.haslayer(UDP) and reply[UDP].sport == TARGET_PORT :
             print(f"[УСПЕХ ТЕСТА/ИНФО] Получен UDP ответ с порта {TARGET_PORT}. Порт ОТКРЫТ и сервис ответил.")
        else:
            print("[ИНФО] Получен неожиданный тип ответа.")
    else:
        print(f"[ИНФО/ПРОВЕРЬ ФАЕРВОЛ] Нет ответа на UDP пакет от {VM_IP}:{TARGET_PORT} в течение {TIMEOUT_SECONDS} секунд.")
        print("   Это может означать, что порт ОТКРЫТ и сервис не ответил (типично для некоторых UDP),")
        print("   ЛИБО порт ЗАБЛОКИРОВАН фаерволом (действие DROP).")

except PermissionError:
    print("[ОШИБКА] Недостаточно прав. Пожалуйста, запустите скрипт с sudo.")
except Exception as e:
    print(f"[ОШИБКА] Произошла непредвиденная ошибка: {e}")

print(f"--- Тест UDP порта {TARGET_PORT} завершен ---\n")