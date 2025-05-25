# scapy_test_tcp_open.py
from scapy.all import IP, TCP, sr1, conf
import sys

# --- НАСТРОЙКИ ---
VM_IP = "10.211.55.13"
TARGET_PORT = 8080 # Порт, который должен быть ОТКРЫТ на VM и разрешен фаерволом
# conf.iface = "en0"
TIMEOUT_SECONDS = 2
# --- КОНЕЦ НАСТРОЕК ---

print(f"--- Тест TCP порта {TARGET_PORT} (должен быть открыт) на {VM_IP} ---")

try:
    # Создаем TCP SYN пакет
    # Используем случайный порт источника (или можно задать свой)
    ip_layer = IP(dst=VM_IP)
    tcp_layer = TCP(dport=TARGET_PORT, flags="S") # S - SYN флаг
    packet = ip_layer/tcp_layer

    print(f"Отправка TCP SYN пакета на {VM_IP}:{TARGET_PORT}...")
    reply = sr1(packet, timeout=TIMEOUT_SECONDS, verbose=0)

    if reply:
        print(f"[УСПЕХ/ПРОВЕРКА] Получен ответ от {reply.src}:")
        reply.show()
        if reply.haslayer(TCP):
            if reply[TCP].flags == "SA": # SA - SYN-ACK флаг (порт открыт)
                print(f"Флаги TCP: SYN-ACK. Порт {TARGET_PORT} вероятнее всего ОТКРЫТ и слушается.")
                # Можно отправить RST, чтобы закрыть полуоткрытое соединение
                rst_packet = IP(dst=VM_IP)/TCP(sport=reply[TCP].dport, dport=TARGET_PORT, flags="R", seq=reply[TCP].ack, ack=reply[TCP].seq + 1)
                send(rst_packet, verbose=0)
                print("Отправлен RST для закрытия соединения.")
            elif reply[TCP].flags == "RA": # RA - RST-ACK флаг (порт закрыт)
                print(f"[ПРОВЕРЬ ФАЕРВОЛ/СЕРВИС] Флаги TCP: RST-ACK. Порт {TARGET_PORT} вероятнее всего ЗАКРЫТ (сервис не слушает или фаервол активно отклоняет).")
            else:
                print(f"[ПРОВЕРКА] Неожиданные флаги TCP: {reply[TCP].flags}")
        else:
            print("[ПРОВЕРКА] Ответ не содержит TCP слоя.")
    else:
        print(f"[ПРОВЕРЬ ФАЕРВОЛ] Нет ответа на TCP SYN от {VM_IP}:{TARGET_PORT} в течение {TIMEOUT_SECONDS} секунд.")
        print("   Возможные причины: Порт заблокирован фаерволом (DROP), VM выключена, неверный IP, сетевые проблемы.")

except PermissionError:
    print("[ОШИБКА] Недостаточно прав. Пожалуйста, запустите скрипт с sudo.")
except Exception as e:
    print(f"[ОШИБКА] Произошла непредвиденная ошибка: {e}")

print(f"--- Тест TCP порта {TARGET_PORT} завершен ---\n")