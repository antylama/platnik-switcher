# Płatnik Switcher

Program manipuluje kluczami rejestru aby przełączać bazę Płatnika. Wymaga restartu Płatnika.

*Uwaga: Program nie wspiera autoryzacji systemu Windows i wspiera tylko Microsoft SQL Server w wersji 2012 i póżniejsze.*

## Budowa

Skompiluj program z użyciem MinGW:

```
g++ -s -Os -std=c++17 platnik-switcher.cpp -o platnik-switcher.exe -mwindows
```

## Użycie programu

```platnik-start.exe [plik.mdb|host,port] <katalog> [<użytkownik> <hasło>]```

Przykład:

```platnik-start.exe C:\Płatnik\Baza.mdb mojehaslo```

lub

```platnik-start.exe localhost,1433 BazaPlatnika Administrator mojehaslo```

Wywołanie bez argumentów wyświetli pomoc i aktualne parametry bazy Płatnika.

### Uprawnienia

Zmień uprawnienia dostępu do klucza `Bazaz` rejestru Płatnika jeśli to konieczne,
ewentualnie uruchom program z uprawnieniami administratora (niezalecane).
Uprawnienia powinny umożliwiać pełną kontrolę nad kluczem (`Pełna kontrola` dla 
użytkownika z którego uprawnieniami uruchamiany jest program).
