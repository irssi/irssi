## Project Overview

Irssi is a modular chat client written in C. It is primarily an IRC client, but also supports other protocols like ICB, SILC, XMPP, PSYC, and Quassel through third-party modules. It has a text-based user interface and is highly extensible with Perl scripts.

The project uses the Meson build system. The main dependencies are GLib, OpenSSL, and Perl.

## Building and Running

To build and run the project, you need to have Meson, Ninja, and the required dependencies installed.

**Building:**

```bash
meson Build
ninja -C Build
```

**Running:**

```bash
sudo ninja -C Build install
```

## Development Conventions

The project follows the GNU General Public License. The code style is not explicitly defined, but the existing code seems to follow a consistent style.

The project has a test suite in the `tests/` directory. To run the tests, you can use the following command:

```bash
ninja -C Build test
```
