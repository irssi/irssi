# Neırssi

![Build Status](https://github.com/ailin-nemui/irssi/workflows/Check%20Irssi/badge.svg?branch=master)

Neırssi is a modular text mode chat client mostly compatible with
[Irssi](https://irssi.org). It comes with IRC support built in, and
there are third party [ICB](https://github.com/jperkin/irssi-icb),
[SILC](http://www.silcnet.org/),
[XMPP](http://cybione.org/~irssi-xmpp/) (Jabber),
[PSYC](http://about.psyc.eu/Irssyc) and
[Quassel](https://github.com/phhusson/quassel-irssi) protocol modules
available.

![irssi](https://user-images.githubusercontent.com/5665186/154820868-50c35841-04f4-4f4c-8df9-dd5aa4bbcde8.png)

## [Download information](https://ailin-nemui.github.io/irssi/Getting.html)

#### Development source installation

[Ninja](https://ninja-build.org/) 1.8 and [Meson](https://mesonbuild.com/) 0.53

```
git clone https://github.com/ailin-nemui/irssi
cd irssi
meson Build
ninja -C Build && sudo ninja -C Build install
```

#### Release source installation

* Download [release](https://github.com/ailin-nemui/irssi/releases)
* Verify signature
```
tar xJf irssi-*.tar.xz
cd irssi-*
meson Build
ninja -C Build && sudo ninja -C Build install
```

### Requirements

- [glib-2.32](https://wiki.gnome.org/Projects/GLib) or greater
- [openssl](https://www.openssl.org/)
- [perl-5.6](https://www.perl.org/) or greater (for perl support)
- terminfo or ncurses (for text frontend)

#### See the [INSTALL](INSTALL) file for details

## Documentation

* [New users guide](https://ailin-nemui.github.io/irssi/New-users.html)
* Check the built-in `/HELP`, it has all the details on command syntax
* Other random Irssi documentation on https://irssi.org/documentation/

## [Themes](https://irssi-import.github.io/themes/)

## [Scripts](https://scripts.irssi.org/)

## [Modules](https://ailin-nemui.github.io/irssi/Modules.html)

## [Security information](https://irssi.org/security/)

Please report security issues to staff@irssi.org. Thanks!

## [Bugs](https://github.com/irssi/irssi/issues) / Suggestions / Contributing

Check the GitHub issues if it is already listed in there; if not, open
an issue on GitHub or send a mail to [staff@irssi.org](mailto:staff@irssi.org).

Irssi is always looking for developers. Feel free to submit patches through
GitHub pull requests.

You can also contact the Irssi developers in
[#irssi](https://irssi.org/support/irc/) on irc.libera.chat.
