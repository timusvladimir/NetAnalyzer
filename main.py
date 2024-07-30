from scapy.all import *

def analyze_traffic(interface, count):
    print(f"Анализируем сетевой трафик на интерфейсе {interface}, количество пакетов: {count}")

    packets = sniff(iface=interface, count=count)

    print(f"\nНайдено {len(packets)} пакетов:")
    for packet in packets:
        print(f"Источник: {packet[IP].src} -> Назначение: {packet[IP].dst}")

    # Отобразим информацию о самом последнем пакете
    if packets:
        print("\nИнформация о последнем пакете:")
        print(packets[-1].show())

if __name__ == '__main__':
    interface = "eth0"  # Укажите ваш сетевой интерфейс здесь
    count = 10  # Количество пакетов для анализа

    analyze_traffic(interface, count)

