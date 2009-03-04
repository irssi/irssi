

irssi, http://irssi.org


 * INSTALLATION

See INSTALL file.


 * FILES

 - docs/ directory contains several documents:
    - startup-HOWTO.txt - new users should read this
    - manual.txt - manual I started writing but didn't get it very far :)
    - perl.txt - Perl scripting help
    - formats.txt - How to use colors, etc. with irssi
    - faq.txt - Frequently Asked Questions
    - special_vars.txt - some predefined $variables you can use with irssi


 * ABOUT

Irssi is a modular IRC client that currently has only text mode user
interface, but 80-90% of the code isn't text mode specific, so other
UIs could be created pretty easily. Also, Irssi isn't really even IRC
specific anymore, there's already a working SILC (http://www.silcnet.org)
module available. Support for other protocols like ICQ could be created
some day too.


 * FEATURES

So what's so great about Irssi? Here's a list of some features I can
think of currently:

 - Optional automation - There's lots of things Irssi does for you
   automatically that some people like and others just hate. Things like:
   nick completion, creating new window for newly joined channel, creating
   queries when msgs/notices are received or when you send a msg, closing
   queries when it's been idle for some time, etc.

 - Multiserver friendy - I think Irssi has clearly the best support
   for handling multiple server connections. You can have as many as you
   want in as many ircnets as you want. Having several connections in one
   server works too, for example when you hit the (ircnet's) 10
   channels/connection limit you can just create another connection and
   you hardly notice it. If connection to server is lost, Irssi tries to
   connect back until it's successful. Also channels you were joined
   before disconnection are restored, even if they're "temporarily
   unavailable" because of netsplits, Irssi keeps rejoining back to them.
   Also worth noticing - there's not that stupid "server is bound to this
   window, if this window gets closed the connection closes" thing that
   ircII based clients have.

 - Channel automation - You can specify what channels to join to
   immediately after connected to some server or IRC network. After joined
   to channel, Irssi can automatically request ops for you (or do
   anything, actually) from channel's bots.

 - Window content saving - Say /LAYOUT SAVE when you've put all the
   channels and queries to their correct place, and after restarting
   Irssi, the channels will be joined back into windows where they were
   saved.

 - Tab completing anything - You can complete lots of things with tab:
   nicks, commands, command -options, file names, settings, text format
   names, channels and server names. There's also an excellent /msg
   completion that works transparently with multiple IRC networks.
   Completing channel nicks is also pretty intelligent, it first goes
   through the people who have talked to you recently, then the people who
   have talked to anyone recently and only then it fallbacks to rest of
   the nicks. You can also complete a set of words you've specified, for
   example homepage<tab> changes it to your actual home page URL.

 - Excellent logging - You can log any way you want and as easily or
   hard as you want. With autologging Irssi logs everything to specified
   directory, one file per channel/nick. ircII style /WINDOW LOG ON is
   also supported. There's also the "hard way" of logging - /LOG command
   which lets you specify exactly what you wish to log and where. Log
   rotating is supported with all the different logging methods, you can
   specify how often you want it to rotate and what kind of time stamp to
   use.

 - Excellent ignoring - You can most probably ignore anything any way
   you want. Nick masks, words, regular expressions. You can add
   exceptions to ignores. You can ignore other people's replies in
   channels to nicks you have ignored. You can also specify that the
   specific ignores work only in specific channel(s).

 - Lastlog and scrollback handling - /LASTLOG command has some new
   features: -new option checks only lines that came since you last did
   /LASTLOG command, -away option checks new lines since you last went
   away. Regular expression matches work also, of course. Going to some
   wanted place at scrollback has always been hard with non-GUI clients. A
   search command that jumps around in scrollback in GUI-style is still
   missing from Irssi, but there's something that's almost as good as it.
   /LASTLOG always shows timestamps when the line was printed, even if you
   didn't have timestamps on. Now doing /SB GOTO <timestamp> jumps
   directly to the position in scrollback you wanted. Great feature when
   you want to browse a bit of the discussion what happened when someone
   said your name (as seen in awaylog) or topic was changed (/last
   -topics)


 * BUGS / SUGGESTIONS

See TODO file and http://bugs.irssi.org if it is already listed in there;
if not open a bugreport on http://bugs.irssi.org or send a mail to
staff@irssi.org

You can also contact the Irssi developers on #irssi @ EFnet, Freenode, IRCnet,
Quakenet and Undernet.

The IRCnet channel is for development related questions and discussions.
