# --- 1. Importujemy moduł do dokładnego parsowania daty ---
from datetime import datetime

# --- 2. Funkcja: czyta cały plik logu i zwraca listę linii ---
def read_log(filename):
    """
    Otwiera plik logu (np. sample_auth.log) i zwraca wszystkie linie jako listę.
    Każda linia jest jednym stringiem.
    """
    with open(filename, "r") as f:            # Otwiera plik w trybie odczytu
        lines = f.readlines()                 # Wczytuje wszystkie linie do listy
    return lines                              # Zwraca listę linii

# --- 3. Funkcja: wykrywa brute‑force (wiele nieudanych logowań z jednego IP) ---
def detect_brute_force(lines, threshold=10):
    """
    Przeszukuje linie logów, szukając wpisów z "Failed password".
    Liczy, ile razy dane IP próbowało się zalogować.
    Jeśli przekroczy próg threshold (np. 10), zapisuje je jako brute‑force.
    """
    failed_counts = {}                        # słownik: IP -> liczba nieudanych prób

    for line in lines:                        # dla każdej linijki logu
        if "Failed password" in line:         # czy w linii jest "Failed password"?
            parts = line.split()              # dzieli linię na słowa (po spacji)
            ip = parts[-4]                    # wyłuskuje IP (zwykle 4. wyraz od końca)
            # jeśli IP jest już w słowniku, zwiększ licznik, jeśli nie – zacznij od 1
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    # po przejściu wszystkich linii, sprawdzamy, które IP przekroczyły próg
    for ip, count in failed_counts.items():
        if count >= threshold:                # jeśli liczba prób >= threshold
            print(f"⚠️ Brute‑force z IP: {ip}, prób: {count}")

# --- 4. Funkcja: wykrywa podejrzane IP (wiele różnych userów z jednego IP) ---
def detect_suspicious_ips(lines, min_users=5):
    """
    Dla linii z "Failed password" zlicza, ile różnych użytkowników próbowało z jednego IP.
    Jeśli IP ma więcej niż min_users różnych userów, zaznacza je jako podejrzane.
    """
    ip_users = {}                             # słownik: IP -> set unikalnych userów

    for line in lines:
        if "Failed password" in line:
            parts = line.split()
            user = parts[-8]                  # wyłuskuje nazwę usera (przybliżony indeks)
            ip = parts[-4]                    # IP (zwykle 4. wyraz od końca)

            # jeśli IP nie jest jeszcze w słowniku, tworzymy pusty zbiór userów
            if ip not in ip_users:
                ip_users[ip] = set()

            ip_users[ip].add(user)            # dodajemy usera do zbioru (bez duplikatów)

    # sprawdzamy, które IP mają dużo różnych userów
    for ip, users in ip_users.items():
        if len(users) >= min_users:
            print(f"🔴 Podejrzane IP (wiele userów): {ip}, userzy: {users}")

# --- 5. Funkcja: wykrywa logowania w nietypowych godzinach ---
def detect_unusual_hours(lines, start_hour=8, end_hour=20):
    """
    Przeszukuje linie z "Accepted" (udane logowania) i sprawdza godzinę.
    Jeśli logowanie jest poza okresem start_hour–end_hour (np. 8–20), zaznacza je jako nietypowe.
    """
    suspicious_hours = set()                  # zbiór IP, które logowały się w nietypowych godzinach

    for line in lines:
        if "Accepted" in line:                # tylko udane logowania
            parts = line.split()
            time_str = parts[2]               # np. 02:15:23 (3. słowo w linii)
            hour = int(time_str.split(":")[0])  # dzieli czas po ":" i bierze pierwszą część (godzinę)
            ip = parts[-4]                    # IP z tej linii

            # jeśli godzina jest poza zakresem (np. < 8 lub > 20)
            if hour < start_hour or hour > end_hour:
                suspicious_hours.add(ip)      # dodajemy IP do zbioru podejrzanych godzin

    # wypisujemy wszystkie IP, które logowały się w nietypowych godzinach
    for ip in suspicious_hours:
        print(f"🕒 Logowanie w nietypowych godzinach z IP: {ip}")

# --- 6. Główna część programu (uruchamiana tylko gdy uruchamiasz plik) ---
if __name__ == "__main__":
    """
    To blok kodu wykona się tylko wtedy, gdy odpalisz plik bezpośrednio (python log_analyzer.py).
    """
    # 1. Wczytujemy logi z pliku
    lines = read_log("sample_auth.log.txt")

    # 2. Wykrywamy brute‑force (próg 10 nieudanych prób)
    print("🔍 Analiza brute‑force:")
    detect_brute_force(lines, threshold=10)

    # 3. Wykrywamy podejrzane IP (min. 5 różnych userów z jednego IP)
    print("\n🔍 Analiza podejrzanych IP:")
    detect_suspicious_ips(lines, min_users=5)

    # 4. Wykrywamy logowania w nietypowych godzinach (8–20)
    print("\n🔍 Analiza nietypowych godzin logowania:")
    detect_unusual_hours(lines, start_hour=8, end_hour=20)