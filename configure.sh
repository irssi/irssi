#!/bin/sh

# configure.sh - Inteligentny, przenośny skrypt konfiguracyjny dla irssi-dev

# --- Funkcje Pomocnicze ---
ask_yes_no() {
    while true; do
        printf "$1 [y/n]: "
        read -r answer
        case "$answer" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) printf "Proszę odpowiedzieć 'y' lub 'n'.\n" ;;
        esac
    done
}

cleanup_backups() {
    printf "🧹 Czyszczenie plików tymczasowych (.bak)...
"
    find . -name "*.bak" -type f -delete
}

# --- Krok 1: Wykrywanie OS i ustawianie domyślnych ścieżek ---
OS_TYPE=$(uname -s)
DEFAULT_SYSTEM_PREFIX="/usr/local"
DEFAULT_USER_PREFIX="$HOME/.local"

# --- Krok 2: Wykrywanie istniejącego irssi ---
printf "🔎 Sprawdzanie istniejącej instalacji irssi...\n"
EXISTING_IRSSI_BIN=$(command -v irssi)
EXISTING_IRSSI_DIR="$HOME/.irssi"
TARGET_NAME="irssi"

if [ -n "$EXISTING_IRSSI_BIN" ] || [ -d "$EXISTING_IRSSI_DIR" ]; then
    printf "⚠️ Wykryto istniejącą instalację irssi!\n"
    if [ -n "$EXISTING_IRSSI_BIN" ]; then
        printf "   - Plik binarny znaleziony w: %s\n" "$EXISTING_IRSSI_BIN"
    fi
    if [ -d "$EXISTING_IRSSI_DIR" ]; then
        printf "   - Katalog konfiguracyjny znaleziony w: %s\n" "$EXISTING_IRSSI_DIR"
    fi

    printf "\nMożesz zainstalować tę wersję jako główny program lub obok, pod inną nazwą.\n"
    printf "1. Zastąp (zainstaluj jako 'irssi')\n"
    printf "2. Zainstaluj obok (jako 'arssi')\n"

    while true; do
        printf "Wybierz opcję [1/2]: "
        read -r choice
        case "$choice" in
            1)
                printf "Wybrano instalację jako 'irssi'.\n"
                printf "🚨 Pamiętaj, aby ręcznie odinstalować poprzednią wersję za pomocą menedżera pakietów, aby uniknąć konfliktów.\n"
                if ! ask_yes_no "Kontynuować?"; then printf "Przerwano.\n"; exit 1; fi
                TARGET_NAME="irssi"
                break
                ;;
            2)
                printf "Wybrano instalację obok pod nazwą 'arssi'.\n"
                TARGET_NAME="arssi"
                break
                ;;
            *)
                printf "Nieprawidłowy wybór.\n"
                ;;
        esac
    done
fi

# --- Krok 3: Wybór typu instalacji (Systemowa vs. Użytkownika) ---
printf "\nWybierz typ instalacji:\n"
printf "1. Systemowa (dla wszystkich użytkowników, wymaga sudo, zalecane: %s)\n" "$DEFAULT_SYSTEM_PREFIX"
printf "2. Lokalna (tylko dla Ciebie, nie wymaga sudo, zalecane: %s)\n" "$DEFAULT_USER_PREFIX"

while true; do
    printf "Wybierz opcję [1/2]: "
        read -r choice
    case "$choice" in
        1)
            INSTALL_PREFIX="$DEFAULT_SYSTEM_PREFIX"
            SUDO_NEEDED="tak"
            break
            ;;
        2)
            INSTALL_PREFIX="$DEFAULT_USER_PREFIX"
            SUDO_NEEDED="nie"
            break
            ;;
        *)
            printf "Nieprawidłowy wybór.\n"
            ;;
    esac
done

# --- Krok 4: Dynamiczna zmiana nazwy (jeśli to konieczne) ---
MESON_OPTS=""
if [ "$TARGET_NAME" != "irssi" ]; then
    printf "\n🔧 Konfiguruj
ę projektu do używania nazwy '%s'...
" "$TARGET_NAME"
    MESON_OPTS="-Dpkgname=$TARGET_NAME"

    # Zmiana nazwy binarnej w meson.build
    sed -i.bak "s/executable('irssi'/executable('$TARGET_NAME'/" src/fe-text/meson.build
    
    # Zmiana katalogu domowego w common.h
    sed -i.bak "s|\"%s/.irssi\"|\"%s/.$TARGET_NAME\"|" src/common.h
    
    # Zmiana ścieżek #include w całym kodzie
    printf "Aktualizowanie ścieżek #include...
"
    for ext in c h xs; do
        find src tests -type f -name "*.$ext" -exec sed -i.bak "s|<irssi/|<$TARGET_NAME/|g" {} \;
    done
    
    printf "✅ Konfiguracja nazwy zakończona.\n"
fi

# --- Krok 5: Uruchomienie procesu budowania ---
BUILD_DIR="$(pwd)/Build"

printf "\n🛠️  Przygotowywanie do budowania w katalogu: %s\n" "$BUILD_DIR"
printf "📦 Prefiks instalacji: %s\n" "$INSTALL_PREFIX"

if [ -d "$BUILD_DIR" ]; then
    printf "Usuwanie istniejącego katalogu Build...
"
    rm -rf "$BUILD_DIR"
fi

printf "\n⚙️  Uruchamianie Meson...
"
if ! meson setup "$BUILD_DIR" -Dprefix="$INSTALL_PREFIX" -Dwith-perl=yes -Dwith-proxy=yes $MESON_OPTS; then
    printf "❌ Błąd podczas konfiguracji Meson. Sprawdź logi powyżej.\n"
    cleanup_backups
    exit 1
fi

printf "\n🔨 Uruchamianie Ninja (kompilacja)...
"
if ! ninja -C "$BUILD_DIR"; then
    printf "❌ Błąd podczas kompilacji. Sprawdź logi powyżej.\n"
    cleanup_backups
    exit 1
fi

# Czyszczenie po udanej kompilacji
cleanup_backups

printf "\n✨ Kompilacja zakończona sukcesem!\n"
printf "Aby zainstalować, uruchom następującą komendę:\n"
if [ "$SUDO_NEEDED" = "tak" ]; then
    printf "sudo ninja -C %s install\n" "$BUILD_DIR"
else
    printf "ninja -C %s install\n" "$BUILD_DIR"
    printf "\nUpewnij się, że katalog '%s/bin' jest dodany do Twojej zmiennej środowiskowej PATH.\n" "$INSTALL_PREFIX"
fi

exit 0
