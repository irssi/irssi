## ANALIZA KROK PO KROKU - FLOW WIADOMOŚCI W IRSSI

### 1. WIADOMOŚCI PRZYCHODZĄCE (od serwera do wyświetlenia)

#### Krok 1: Odbieranie z serwera
**Funkcja**: `irc_parse_incoming()` w `src/irc/core/irc.c:543`
- Czyta dane z socketu przez `net_sendbuffer_receive_line()`
- Emituje sygnał `"server incoming"` z surową linią

#### Krok 2: Parsowanie IRC
**Funkcja**: `irc_parse_incoming_line()` w `src/irc/core/irc.c:528`
- Parsuje prefix (nick, address, tags) przez `irc_parse_prefix()`
- Emituje sygnał `"server event tags"` z parsowanymi danymi

#### Krok 3: Rozpoznanie typu wiadomości
**Funkcja**: `irc_server_event()` w `src/irc/core/irc.c:370`
- Parsuje komendę IRC (PRIVMSG, JOIN, etc.)
- Emituje odpowiedni sygnał np. `"event privmsg"`

#### Krok 4: Konwersja na sygnały wiadomości
**Funkcja**: `event_privmsg()` w `src/fe-common/irc/fe-events.c:42`
- Dekoduje wiadomość przez `recode_in()`
- Rozróżnia kanał vs prywatna
- Emituje `"message public"` lub `"message private"`

#### Krok 5: Obsługa sygnału wiadomości
**Funkcja**: `sig_message_public()` w `src/fe-common/core/fe-messages.c:168`
- Znajduje kanał i nick record
- Pobiera nickmode przez `channel_get_nickmode()`
- Sprawdza highlight przez `hilight_match()`
- **WYWOŁUJE**: `printformat_module("fe-common/core", server, target, level, TXT_PUBMSG, nick, address, msg, nickmode)`

### 2. FORMATOWANIE I THEME

#### Krok 6: printformat_module
**Funkcja**: `printformat_module()` w `src/fe-common/core/printtext.c:101`
- Tworzy `TEXT_DEST_REC` przez `format_create_dest()`
- Wywołuje `printformat_module_dest_args()`

#### Krok 7: Emisja sygnału formatowania
**Funkcja**: `printformat_module_dest_charargs()` w `src/fe-common/core/printtext.c:64`
- Pobiera theme przez `window_get_theme()`
- **EMITUJE**: `signal_emit_id(signal_print_format, 5, theme, module, dest, formatnum, arglist)`

#### Krok 8: Obsługa sygnału formatowania
**Funkcja**: `sig_print_format()` w `src/fe-common/core/printtext.c:459`
- **WYWOŁUJE**: `format_get_text_theme_charargs(theme, module, dest, formatnum, arglist)`

#### Krok 9: Pobieranie tekstu z theme
**Funkcja**: `format_get_text_theme_charargs()` w `src/fe-common/core/formats.c:831`
- Znajduje moduł theme w `theme->modules`
- Pobiera expanded format: `text = module_theme->expanded_formats[formatnum]`
- **WYWOŁUJE**: `format_get_text_args(dest, text, args)`

#### Krok 10: Parsowanie expandos i zmiennych
**Funkcja**: `format_get_text_args()` w `src/fe-common/core/formats.c:737`
- Iteruje przez tekst formatujący
- Gdy napotka `$`, wywołuje `parse_special()`

#### Krok 11: Parsowanie expandos
**Funkcja**: `parse_special()` w `src/core/special-vars.c:425`
- Parsuje składnię `$[alignment]variable`
- **WYWOŁUJE**: `get_special_value()` → `get_variable()` → `get_long_variable_value()`

#### Krok 12: Wykonanie expando
**Funkcja**: `get_long_variable_value()` w `src/core/special-vars.c:95`
- **WYWOŁUJE**: `func = expando_find_long(key)`
- **WYWOŁUJE**: `return func(server, item, free_ret)` ← **TU SĄ NASZE EXPANDOS!**

### 3. WIADOMOŚCI WYCHODZĄCE (nasze wiadomości)

#### Krok 1: Input od użytkownika
**Funkcja**: Obsługa klawiatury w `src/fe-text/gui-readline.c`
- Przechwytuje Enter, wywołuje `signal_emit("send command", ...)`

#### Krok 2: Parsowanie komendy
**Funkcja**: `cmd_msg()` lub podobne w `src/irc/core/irc-commands.c`
- Wysyła PRIVMSG do serwera
- Emituje `"message own_public"` lub `"message own_private"`

#### Krok 3: Formatowanie własnej wiadomości
**Funkcja**: `sig_message_own_public()` w `src/fe-common/core/fe-messages.c:281`
- Pobiera nickmode przez `channel_get_nickmode(channel, server->nick)`
- **WYWOŁUJE**: `printformat_module("fe-common/core", server, target, level, TXT_OWN_MSG, server->nick, target, msg, nickmode)`

**Dalej flow jest identyczny jak dla wiadomości przychodzących od kroku 6.**
