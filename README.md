# SSH Log Analyzer (Python)

Projekt: Security_Log_Analyzer

## Opis projektu
SSH Log Analyzer to narzędzie CLI napisane w Pythonie do analizy logów uwierzytelniania (auth.log).  
Celem projektu jest wykrywanie potencjalnych zagrożeń bezpieczeństwa oraz anomalii w logowaniach użytkowników.  

Projekt symuluje podstawowe mechanizmy analizy logów stosowane w systemach monitoringu bezpieczeństwa (SIEM).

---

## Funkcjonalności

- Parsowanie logów SSH (auth.log)  
- Ekstrakcja danych: adres IP, użytkownik, timestamp, status logowania  
- Wykrywanie ataków brute‑force (wiele nieudanych prób logowania z jednego IP)  
- Identyfikacja podejrzanych adresów IP (wiele różnych użytkowników z jednego IP)  
- Wykrywanie logowań w nietypowych godzinach (poza standardowym zakresem 8–20)  
- Analiza heurystyczna danych logów  

---

## Technologie

- Python 3  
- Przetwarzanie tekstu (string processing)  
- Struktury danych: słowniki, zbiory  
- Podstawy cyberbezpieczeństwa (log analysis)  

---

## Struktura projektu

- `log_analyzer.py` – główny skrypt analizujący logi  
- `sample_auth.log` – przykładowy plik logów SSH do testowania  
- `README.md` – dokumentacja projektu  