# The Ultimate IRC Experience: Irssi ✨ 🚀

Irssi is the modular, **text-mode chat client** that puts you in control. 🧑‍💻 It comes with built-in **IRC** support, and its extensible design lets you connect to other chat networks, including **ICB** 💬, **SILC** 🔒, **XMPP** (Jabber) 🕊️, **PSYC** 🧠, and **Quassel** 🏘️, via third-party modules. It’s the perfect tool for developers, sysadmins, and anyone who prefers the power and efficiency of the command line. 💻

-----

## Getting Started 🚀

### Installation 🛠️

There are a few ways to get Irssi up and running. If you're looking to contribute to development, you'll want the latest source. For a stable release, you can download a pre-packaged tarball. 📦

**Development Source Installation**

To get the absolute latest features and fixes, clone the Git repository and build the project using **Ninja** and **Meson**. 👨‍💻

```sh
git clone https://github.com/irssi/irssi
cd irssi
meson Build
ninja -C Build && sudo ninja -C Build install
```

**Release Source Installation**

For a stable, tested version, download the official release from GitHub. Be sure to verify the signature for a secure installation. 🔐

```sh
tar xJf irssi-*.tar.xz
cd irssi-*
meson Build
ninja -C Build && sudo ninja -C Build install
```

**System Requirements**

Before you start, make sure you have the following dependencies: 👇

  * **glib-2.32** or greater
  * **openssl** 🛡️
  * **perl-5.8** or greater (for Perl support) 🧩
  * **terminfo** or **ncurses** (for the text frontend) 🖥️

For more detailed instructions, check the **INSTALL** file. 📄

-----

## Dive into the Details 📖

### Documentation 📚

Whether you're a new user or a seasoned pro, the Irssi documentation is your best friend. 🤝

  * **New User's Guide** 👶: A gentle introduction to the basics.
  * **Questions and Answers** ❓: Find quick solutions to common issues.
  * **Built-in Help** `/HELP` 💡: Use the `/HELP` command directly in Irssi for detailed information on every command and syntax.

### Customization ✨

Make Irssi your own with a vibrant community of themes, scripts, and modules. 🎨

  * **Themes** 🌈: Customize the look and feel of your chat client.
  * **Scripts** ✍️: Extend functionality with user-created scripts.
  * **Modules** 🏗️: Add support for new protocols or features.

-----

## Community & Support 🫂

### Get Involved 👋

Irssi is an **open-source project** and thrives on community contributions. We're always looking for new developers\! 🌟

  * **Bug Reports & Suggestions** 🐞💡: Have a problem or a great idea? Check the [GitHub issues](https://github.com/irssi/irssi/issues) to see if it's already been reported, or open a new one. You can also email us at **staff@irssi.org**. 📧
  * **Contributions** 💖: Feel free to submit patches via **GitHub pull requests**.
  * **Chat with us\!** 🗣️: You can find the developers and other users in **\#irssi** on irc.libera.chat. 💬

### Security 🛡️

We take security seriously. If you discover a security issue, please report it privately to **staff@irssi.org**. Your help in keeping Irssi secure is greatly appreciated. 🙏
