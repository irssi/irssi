# KOMPLEKSOWY PLAN IMPLEMENTACJI - NOWE PODEJŚCIE

## WYTYCZNE OBOWIĄZKOWE:
1. **Zawsze pamiętaj kontekst**: `msg_flow.md` i `summary.md`
2. **Nie zbaczaj z wyznaczonej ścieżki** - trzymaj się planu
3. **Checkpoint commits**: Po zmianach commit z pushem zawierający info o zmianach i timestamp (data + dokładna godzina)
4. **ZAKAZ `ninja Build install`** - tylko build do sprawdzenia błędów kompilacji

## ANALIZA PROBLEMU

**KLUCZOWA OBSERWACJA**: Po analizie `msg_flow.md` i `summary.md` widzę, że:

1. ❌ **`parse_special` + `ALIGN_COMBINE_MODE`** - już próbowane, problem z kolorami
2. ❌ **Expandos** - nie mają dostępu do `arglist`, zwracają puste stringi  
3. ✅ **NOWE ROZWIĄZANIE**: Modyfikacja na poziomie **`format_get_text_args`** (krok 10 w flow)

## STRATEGIA: INTEGRACJA Z ARGUMENTAMI FORMATOWANIA

### KLUCZOWA IDEA:
Zamiast modyfikować `parse_special` lub tworzyć expandos, **wstrzykniemy dodatkowy parametr padding bezpośrednio do `arglist`** w `format_get_text_args()`.

## PLAN IMPLEMENTACJI

### FAZA 1: Przygotowanie Infrastruktury

#### 1.1 Dodanie ustawień konfiguracyjnych
**Plik**: `src/fe-common/core/fe-settings.c`
```c
// Dodać do settings_add_*():
settings_add_bool("lookandfeel", "nick_column_enabled", FALSE);
settings_add_int("lookandfeel", "nick_column_width", 12);
```

#### 1.2 Dodanie flag do TEXT_DEST_REC
**Plik**: `src/fe-common/core/printtext.h`
```c
typedef struct {
    // ... istniejące pola
    int flags;  // nowe pole dla flag formatowania
} TEXT_DEST_REC;

#define PRINT_FLAG_NICK_COLUMN 0x01
```

### FAZA 2: Modyfikacja Flow Formatowania

#### 2.1 Ustawienie flagi w obsłudze wiadomości
**Plik**: `src/fe-common/core/fe-messages.c`

W funkcjach `sig_message_public()` i `sig_message_own_public()`:
```c
// Po utworzeniu dest przez format_create_dest()
if (settings_get_bool("nick_column_enabled")) {
    dest.flags |= PRINT_FLAG_NICK_COLUMN;
}
```

#### 2.2 Główna logika w format_get_text_args
**Plik**: `src/fe-common/core/formats.c`

W funkcji `format_get_text_args()` (krok 10 flow), **PRZED** pętlą parsowania:

```c
// Sprawdź czy nick column jest włączony
if (dest && (dest->flags & PRINT_FLAG_NICK_COLUMN)) {
    // Znajdź parametry mode i nick w arglist
    char *mode = NULL, *nick = NULL;
    
    // Dla TXT_PUBMSG: args[0]=nick, args[3]=nickmode
    // Dla TXT_OWN_MSG: args[0]=nick, args[3]=nickmode
    if (args && args[0] && args[3]) {
        nick = args[0];
        mode = args[3];
        
        // Oblicz padding
        int width = settings_get_int("nick_column_width");
        int mode_len = strlen(mode);
        int nick_len = strlen(nick);
        int total_len = mode_len + nick_len;
        
        if (total_len < width) {
            int padding_len = width - total_len;
            char *padding = g_strnfill(padding_len, ' ');
            
            // Wstrzyknij padding jako nowy parametr na początku
            // Przesuń wszystkie argumenty o 1 pozycję w prawo
            // args[0] = padding, args[1] = nick, args[4] = mode
            // Theme będzie używać: $0 (padding) + $4 (mode) + $1 (nick)
        }
    }
}
```

### FAZA 3: Modyfikacja Theme

#### 3.1 Aktualizacja abstracts w default.theme
```theme
# Gdy nick_column_enabled = ON, argumenty są przesunięte:
# $0 = padding (nowy)
# $1 = nick (przesunięty z $0) 
# $4 = mode (przesunięty z $3)

# Podstawowy abstract z padding
msgnick = "%K<%n$0%B$4%N%g$1%K>%n %|";

# Own messages
ownmsgnick = "{msgnick $0 $4 $1}";

# Public messages  
pubmsgnick = "{msgnick $0 $4 $1}";
```

### FAZA 4: Testowanie i Debugowanie

#### 4.1 Dodanie debug outputu
```c
// W format_get_text_args() dodać:
if (settings_get_bool("debug_nick_column")) {
    printf("DEBUG: nick_column - padding='%s', mode='%s', nick='%s'\n", 
           padding, mode, nick);
}
```

#### 4.2 Checkpoint commit
```bash
git add -A
git commit -m "[nick_column] FAZA 1-4: Infrastruktura + logika padding - 2025-01-24 15:30"
git push origin irssip
```

## HARMONOGRAM IMPLEMENTACJI

### Dzień 1: Infrastruktura
- [ ] Dodanie ustawień (`nick_column_enabled`, `nick_column_width`)
- [ ] Dodanie flag do `TEXT_DEST_REC`
- [ ] Checkpoint commit

### Dzień 2: Logika formatowania  
- [ ] Modyfikacja `sig_message_public()` i `sig_message_own_public()`
- [ ] Implementacja logiki padding w `format_get_text_args()`
- [ ] Checkpoint commit

### Dzień 3: Theme i testowanie
- [ ] Aktualizacja `default.theme`
- [ ] Dodanie debug outputu
- [ ] Build test (bez install)
- [ ] Checkpoint commit

## PRZEWIDYWANE WYZWANIA

### 1. Przesunięcie argumentów
**Problem**: Wstrzyknięcie padding przesuwa wszystkie argumenty
**Rozwiązanie**: Dokładne mapowanie argumentów w theme

### 2. Kompatybilność wsteczna
**Problem**: Theme musi działać z wyłączonym nick_column
**Rozwiązanie**: Warunki w theme lub osobne abstracts

### 3. Różne formaty wiadomości
**Problem**: `TXT_PUBMSG`, `TXT_OWN_MSG`, `TXT_PUBMSG_HILIGHT` mają różne argumenty
**Rozwiązanie**: Mapowanie per format type

## KRYTERIA SUKCESU

✅ **Wyrównanie działa** - nicki wyrównane do prawej w kolumnie  
✅ **Kolory zachowane** - osobne kolory dla mode i nick  
✅ **Konfigurowalność** - szerokość przez ustawienia  
✅ **Kompatybilność** - działa z wyłączonym nick_column  
✅ **Brak wpływu na resztę** - standardowe formatowanie nietknięte  
