# Płatnik Switcher

Program manipuluje kluczami rejestru aby przełączać bazę Płatnika. Wymaga restartu Płatnika.

## Budowa

Skompiluj program z użyciem MinGW:

```
g++ -std=c++17 platnik-switcher.cpp -o platnik-switcher.exe -mwindows
```

## Użycie programu

```platnik-start.exe [plik.mdb|host,port] <katalog> [<użytkownik> <hasło>]```

Przykład:

```platnik-start.exe C:\Płatnik\Baza.mdb mojehaslo```

lub

```platnik-start.exe localhost,1433 BazaPlatnika Administrator mojehaslo```

Wywołanie bez argumentów wyświetli pomoc i aktualne parametry bazy Płatnika.
