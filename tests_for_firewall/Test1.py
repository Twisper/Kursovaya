# scapy_test_icmp.py
from scapy.all import IP, ICMP, sr1, conf
import sys

# --- НАСТРОЙКИ ---
VM_IP = "10.211.55.13"  # Замени на IP твоей Linux VM
# conf.iface = "en0"  # Раскомментируй и укажи свой интерфейс, если нужно
TIMEOUT_SECONDS = 5
# --- КОНЕЦ НАСТРОЕК ---

print(f"--- Тест ICMP (Ping) на {VM_IP} ---")

try:
    # Создаем ICMP Echo Request пакет
    packet = IP(dst=VM_IP)/ICMP()

    print(f"Отправка ICMP пакета на {VM_IP}...")
    # sr1() отправляет пакет и возвращает первый полученный ответ
    reply = sr1(packet, timeout=TIMEOUT_SECONDS, verbose=0)

    if reply:
        print(f"[УСПЕХ] Получен ответ от {reply.src}:")
        reply.show() # Показываем детали ответного пакета
        if reply.haslayer(ICMP) and reply[ICMP].type == 0: # 0 - Echo Reply
             print("Тип ICMP: Echo Reply (ответ на пинг)")
        else:
             print("Тип ICMP: не Echo Reply (неожиданный ответ)")
    else:
        print(f"[ПРОВЕРЬ ФАЕРВОЛ] Нет ответа от {VM_IP} в течение {TIMEOUT_SECONDS} секунд.")
        print("   Возможные причины: ICMP заблокирован фаерволом, VM выключена, неверный IP, сетевые проблемы.")

except PermissionError:
    print("[ОШИБКА] Недостаточно прав. Пожалуйста, запустите скрипт с sudo.")
except Exception as e:
    print(f"[ОШИБКА] Произошла непредвиденная ошибка: {e}")

print("--- Тест ICMP завершен ---\n")