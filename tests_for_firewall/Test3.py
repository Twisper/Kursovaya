# scapy_test_tcp_closed.py
from scapy.all import IP, TCP, sr1, conf
import sys

# --- НАСТРОЙКИ ---
VM_IP = "10.211.55.13"
TARGET_PORT = 12345 # Порт, который должен быть ЗАКРЫТ/ЗАБЛОКИРОВАН на VM
# conf.iface = "en0"
TIMEOUT_SECONDS = 3 # Можно увеличить таймаут, если ожидаем DROP
# --- КОНЕЦ НАСТРОЕК ---

print(f"--- Тест TCP порта {TARGET_PORT} (должен быть закрыт/заблокирован) на {VM_IP} ---")

try:
    ip_layer = IP(dst=VM_IP)
    tcp_layer = TCP(dport=TARGET_PORT, flags="S")
    packet = ip_layer/tcp_layer

    print(f"Отправка TCP SYN пакета на {VM_IP}:{TARGET_PORT}...")
    reply = sr1(packet, timeout=TIMEOUT_SECONDS, verbose=0)

    if reply:
        print(f"Получен ответ от {reply.src}:")
        reply.show()
        if reply.haslayer(TCP):
            if reply[TCP].flags == "RA": # RST-ACK
                print(f"[УСПЕХ ТЕСТА] Флаги TCP: RST-ACK. Порт {TARGET_PORT} ЗАКРЫТ (сервис не слушает или фаервол активно отклоняет REJECT).")
            elif reply[TCP].flags == "SA": # SYN-ACK
                print(f"[ПРОВЕРЬ ФАЕРВОЛ] Флаги TCP: SYN-ACK. Порт {TARGET_PORT} ОТКРЫТ! Это не ожидалось.")
            else:
                print(f"[ПРОВЕРКА] Неожиданные флаги TCP: {reply[TCP].flags}")
        else:
            print("[ПРОВЕРКА] Ответ не содержит TCP слоя.")
    else:
        print(f"[УСПЕХ ТЕСТА] Нет ответа на TCP SYN от {VM_IP}:{TARGET_PORT} в течение {TIMEOUT_SECONDS} секунд.")
        print("   Это ожидаемо, если фаервол блокирует порт (действие DROP).")

except PermissionError:
    print("[ОШИБКА] Недостаточно прав. Пожалуйста, запустите скрипт с sudo.")
except Exception as e:
    print(f"[ОШИБКА] Произошла непредвиденная ошибка: {e}")

print(f"--- Тест TCP порта {TARGET_PORT} завершен ---\n")