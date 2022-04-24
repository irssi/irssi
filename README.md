# [Irssi](https://irssi.org)

![Build Status](https://github.com/irssi/irssi/workflows/Check%20Irssi/badge.svg?branch=master)

Irssi is a modular text mode chat client. It comes with IRC support
built in, and there are third party
[ICB](https://github.com/jperkin/irssi-icb),
[SILC](http://www.silcnet.org/),
[XMPP](http://cybione.org/~irssi-xmpp/) (Jabber),
[PSYC](http://about.psyc.eu/Irssyc) and
[Quassel](https://github.com/phhusson/quassel-irssi) protocol modules
available.

![irssi](https://user-images.githubusercontent.com/5665186/32180643-cf127f60-bd92-11e7-8aa2-882313ce1d8e.png)

## [Download information](https://irssi.org/download/)

#### Development source installation

[Ninja](https://ninja-build.org/) 1.5 and [Meson](https://mesonbuild.com/) 0.49

```
git clone https://github.com/irssi/irssi
cd irssi
meson Build
ninja -C Build && sudo ninja -C Build install
```

#### Release source installation

* Download [release](https://github.com/irssi/irssi/releases)
* [Verify](https://irssi.org/download/#release-sources) signature
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

## [Documentation](https://irssi.org/documentation/)

* [Frequently Asked Questions](https://irssi.org/documentation/faq)
* [Startup How-To](https://irssi.org/documentation/startup)
* Check the built-in `/HELP`, it has all the details on command syntax

## [Themes](https://irssi-import.github.io/themes/)

## [Scripts](https://scripts.irssi.org/)

## [Modules](https://irssi.org/modules/)

## [Security information](https://irssi.org/security/)

Please report security issues to staff@irssi.org. Thanks!

## [Bugs](https://github.com/irssi/irssi/issues) / Suggestions / [Contributing](https://irssi.org/development/)

Check the GitHub issues if it is already listed in there; if not, open
an issue on GitHub or send a mail to [staff@irssi.org](mailto:staff@irssi.org).

Irssi is always looking for developers. Feel free to submit patches through
GitHub pull requests.

You can also contact the Irssi developers in
[#irssi](https://irssi.org/support/irc/) on irc.libera.chat.
