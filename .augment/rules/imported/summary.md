---
type: "always_apply"
---

# irssip - Informacje Krytyczne dla Rozwoju I Implementacji

## Zasady Separacji od Systemowego irssi
Nie używamy nazwy binarnej `irssi` ani standardowych folderów, w których instaluje się oryginalne irssi. Nie używamy również `~/.irssi` jako katalogu domowego. Wszystko po to, by rozwój nie kolidował z systemowym irssi i jego bibliotekami (używamy nowszej wersji niż pakiet zainstalowany).

### Konwencje Nazewnictwa
Plik binarny oraz podstawowa nazwa dla używanych katalogów to **irssip** (od irssi panels):
- Plik binarny: `irssip`
- Katalog instalacji: `/opt/irssip`
- Katalog domowy: `~/.irssip`

### Konfiguracja Środowiska Deweloperskiego
Dla przyspieszenia i ułatwienia testów na żywo, pliki config i default.theme w rzeczywistości znajdują się w naszym workspace:

```bash
ls -la /Users/kfn/.irssip/config
lrwxr-xr-x 1 kfn staff 27 Aug 23 22:13 /Users/kfn/.irssip/config -> /Users/kfn/irssi/config_dev

ls -la /Users/kfn/.irssip/default.theme
lrwxr-xr-x 1 kfn staff 37 Aug 23 02:59 /Users/kfn/.irssip/default.theme -> /Users/kfn/irssi/themes/default.theme
```

## Filozofia Rozwoju

### Zasady KISS (Keep It Simple Stupid)
- Wszelkie wprowadzane zmiany/funkcje mają oddawać ducha prostoty
- Implementacje nie mogą zmieniać działania istniejących mechanizmów
- Zachowanie wstecznej kompatybilności jest priorytetem
- Nowe funkcje powinny być opcjonalne - możliwe do wyłączenia w ustawieniach lub nieaktywne do czasu wywołania

### Proces Deweloperski
1. **Checkpointy**: Przed wprowadzaniem większych zmian zawsze robimy commit roboczy
2. **Testowanie**: Tylko ja testuję wprowadzone zmiany. Ty możesz testować Build lokalnie bez instalacji
3. **Budowanie**: Proces budowania do testów:
```bash
sudo rm -rf /opt/irssip && rm -rf $(pwd)/Build && \
meson setup $(pwd)/Build -Dprefix=/opt/irssip -Dwith-perl=yes -Dwith-proxy=yes && \
ninja -C Build && sudo ninja -C Build install
```

### Pliki Konfiguracyjne
W przypadku zmian wymagających modyfikacji plików config lub theme, edytujemy:
- `/Users/kfn/irssi/config_dev`
- `/Users/kfn/irssi/themes/default.theme`

## Aktualne Zmiany względem Standardowego irssi

### 1. Natywna Obsługa Paneli Bocznych
- **Panel lewy**: Lista okien/kanałów/query z sortowaniem i obsługą myszy
- **Panel prawy**: Lista nicków (nicklist)
- **Cel**: Efekt podobny do WeeChat - łatwe przemieszczanie się po kanałach i query
- **Funkcjonalność**: Klik na element przenosi do okna lub otwiera nowe query

### 2. Modyfikacja Wyświetlania WHOIS
Wyświetlanie outputu komendy whois w aktualnie aktywnym oknie zamiast w oknie status czy sieci

## Aktualny Projekt: Wyrównanie Nicków w Oknie Czatu

### Cel Implementacji
Stała szerokość pola z nickiem osoby piszącej na kanale z wyrównaniem do prawej, aby uzyskać efekt jednej kolumny dla wszystkich wiadomości bez konieczności używania zewnętrznych skryptów jak nm2.

### Oczekiwany Efekt Wizualny
```
22:11:35      @yooz │ no działa ;]
22:12:24    @nosfar │ starsze rzeczy ;p
22:12:38      @yooz │ to zamknij oczy
22:14:22        DMZ │ ✅ Link dodany do bazy!
22:14:22      +iBot │ YouTube  Tytuł: LIVE Gemini
22:14:22  LinkShor> │ Skrócony link dla yooz: https://tinyurl.com/yrqbfxeb
```

Alternatywny przykład z nawiasami kątowymi i skróceniem długiego nicka dodatkowy > informuje że to nie pełny nick:
```
21:36:06> <   @kofany> bittersweets outstript
21:36:16> <   @kofany> sarcomas oven's pebble's
21:37:46> <+testNick>> truncation's debarked Allie
21:37:56> <+testNick>> griming surtax's intermediary's
```

### Wymagania Techniczne
- Implementacja **musi** wspierać aktualne formatowanie linii w theme
- Zachowanie kompatybilności z istniejącymi motywami
- Możliwość konfiguracji szerokości pola wyświetlania nicka z formatowamiem.
- Obsługa długich nicków z obcinaniem i wskaźnikiem

## Dotychczasowe Próby Implementacji

[Tu następuje szczegółowa dokumentacja techniczna z poprzedniego dokumentu]

## Standardowe Formatowanie Wiadomości irssi
```
# Oryginalny format (bez wyrównania):
msgnick = "%K<%n$0$1-%K>%n %|";
ownmsgnick = "{msgnick $0 $1-}%g";

# Parametry: $0=tryb(mode) (@,+), $1=nick, wynik: <@nick> wiadomość
```

## Zmodyfikowane Pliki

### 1. `/src/core/special-vars.h`
- Dodano flagę `#define ALIGN_COMBINE_MODE 0x10`
- Rozszerzono system wyrównywania o obsługę kombinacji tryb+nick

### 2. `/src/core/special-vars.c`
- Zmodyfikowano `get_alignment_args()` aby parsować flagę '&': `*flags |= ALIGN_COMBINE_MODE`
- Zaimplementowano logikę kombinacji w `parse_special()`:
  - Pobiera tryb z `arglist[2]` i nick z `arglist[0]`
  - Oblicza dostępną przestrzeń: `total_width - mode_len - 2` (dla nawiasów)
  - Wyrównuje do prawej z wypełnieniem: `"   @nick"`
  - Obcina długie nicki: `"@bardzodlu+"`
  - Zwraca połączony string do przetworzenia przez motyw

### 3. `/themes/default.theme`
- Zaktualizowano komendy formatowania używając składni `$[~&12]0`:
  ```
  own_msg = "{ownmsgnick $[~&12]0}$1";
  pubmsg = "{pubmsgnick $[~&12]0}$1";
  ```
- Dodano obszerną dokumentację i komentarze dotyczące dostosowania kolorów

## Próby Implementacji

### Próba 1: Natywny Mechanizm $[]
Początkowo próbowano użyć standardowego wyrównania irssi: `$[-12]0` i `$[-12]1`

**Problem**: Natywne wyrównanie oddzielało tryb od nicka podczas wyrównywania:
```
Wynik: <@     kofany>  # Tryb z lewej, nick wyrównany do prawej osobno
Wymagane: <     @kofany>  # Wszystko razem, wyrównane do prawej
```

### Próba 2: Rozszerzenie ALIGN_COMBINE_MODE
Rozszerzono `parse_special()` aby łączyć tryb+nick przed zastosowaniem wyrównania używając flagi `&`.

**Osiągnięcie**: Pomyślnie utworzono wyrównane do prawej połączone tryb+nick z odpowiednim wypełnieniem i obcięciem.

**Obecna Ściana**: Ograniczenie interpretacji kolorów w systemie motywów.


### Co Mamy Teraz przykład:
```themes
ownmsgnick = "{msgnick %B$0%N%g$1-%N}%g";
```

Z ALIGN_COMBINE_MODE, `$0` staje się połączonym stringiem `"@kofany"`, więc:
- `%B$0%N` koloruje całe `"@kofany"` na niebiesko
- `%g$1-%N` jest ignorowane (puste po połączeniu)
- **Wynik**: `<     @kofany>` gdzie zarówno @ jak i nick są niebieskie

### Czego Potrzebujemy:
```
Oczekiwane: <     @kofany> gdzie @ jest niebieski (%B) a nick jest zielony (%g)
```

### Główny Problem:
Po połączeniu tryb+nick w kodzie C, motyw otrzymuje jeden parametr zawierający `"@kofany"` jako pojedynczy string. Abstrakcje motywu nie mogą zastosować osobnych kolorów do części połączonego stringa - mogą tylko kolorować cały parametr.

## Wyzwanie Techniczne
Fundamentalny konflikt:
1. **Wymóg wyrównania w obecnej implementacji**: Tryb i nick muszą być połączone przed wyrównaniem aby osiągnąć `<     @nick>` a nie `<@     nick>`
2. **Wymóg kolorów**: Tryb i nick potrzebują osobnego formatowania kolorów z abstrakcji motywu
3. **Obecne ograniczenie**: Po połączeniu w C, motyw widzi pojedynczy string i nie może zastosować osobnych kolorów

## AKTUALNE USTALENIA (2025-01-24)

### Analiza Flow Wiadomości
Przeprowadzono szczegółową analizę flow wiadomości w Irssi od otrzymania z serwera do wyświetlenia (dokumentacja w `msg_flow.md`). Zidentyfikowano fundamentalny problem z podejściem expandos.

### Problem z Expandos
Expandos nie mają dostępu do `arglist` z formatowania - są wywoływane globalnie bez kontekstu lokalnego formatowania. To powoduje, że zwracają puste stringi zamiast rzeczywistych wartości mode i nick.

### Rekomendowane Rozwiązanie
**Rozszerzenie systemu wyrównania w `parse_special`** zamiast expandos:

1. **Nowa składnia**: `$[~&nick_column]0` - wyrównanie z flagą nick_column
2. **Zachowuje osobne parametry** - mode ($0) i nick ($1) pozostają oddzielne dla kolorowania
3. **Zgodne z roadmapą Irssi** - "variable/dynamic expandos with arguments"
4. **Eleganckie kodowo** - rozszerza istniejący system zamiast go obchodzić

### Wymagania Implementacji

- Rozszerzyć `get_alignment_args()` o flagę `&nick_column`
- Dodać `ALIGN_NICK_COLUMN` do special-vars.h
- Implementować logikę kombinowania mode+nick przed wyrównaniem
- Zachować osobne parametry po wyrównaniu dla theme
- Ustawienia: `nick_column_enabled` i `nick_column_width`
