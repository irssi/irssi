#!/bin/sh -e
# Run this to download FAQ and startup-HOWTO from irssi.org

PKG_NAME="Irssi"

site=https://irssi.org

faq=$site/documentation/faq/
howto=$site/documentation/startup/

# remove everything until H1 and optionally 2 DIVs before the
# FOOTER. May need to be adjusted as the source pages change
pageclean_regex='s{.*(?=<h1)}{}s;
s{(\s*<script\s.*?</script>)?\s*(</div>\s*){0,3}<footer.*}{}s;
s{(<.*?)\sclass="(?:highlighter-rouge|highlight)"(.*?>)}{\1\2}g;'

srcdir=`dirname "$0"`
test -z "$srcdir" && srcdir=.
srcdir="$srcdir"/..

if test ! -f "$srcdir"/configure.ac; then
    echo -n "**Error**: Directory \`$srcdir' does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
fi

# detect downloader app
downloader=false

if type curl >/dev/null 2>&1 ; then
    downloader="curl -Ssf"
elif type wget >/dev/null 2>&1 ; then
    downloader="wget -nv -O-"
else
    echo "**Error**: No wget or curl present"
    echo "Install wget or curl, then run syncdocs.sh again"
fi

# detect html converter app
converter=false
if [ "$1" = "-any" ]; then
    any=true
else
    any=false
fi

if type w3m >/dev/null 2>&1 ; then
    converter="w3m -o display_link_number=1 -dump -T text/html"
    any=true
elif type lynx >/dev/null 2>&1 ; then
    converter="lynx -dump -stdin -force_html"
elif type elinks >/dev/null 2>&1 ; then
    converter="elinks -dump -force-html"
else
    echo "**Error**: Neither w3m, nor lynx or elinks present"
    echo "Install w3m, then run syncdocs.sh again"
    exit 1
fi

if ! $any ; then
    echo "**Error**: w3m not present"
    echo "If you want to use lynx or elinks, run syncdocs.sh -any"
    exit 1
fi

check_download() {
    if test "$1" -ne 0 || test ! -e "$2" || test "$(wc -l "$2" | awk '{print $1}')" -le 1 ; then
	rm -f "$2"
	echo "... download failed ( $1 )"
	exit 2
    fi
}

download_it() {
    echo "Downloading $1 from $2 ..."
    ret=0
    $downloader "$2" > "$3".tmp || ret=$?
    check_download "$ret" "$3".tmp
    perl -i -0777 -p -e "$pageclean_regex" "$3".tmp
    perl -i -0777 -p -e 's{\A}{'"<base href='$2'>"'\n}' "$3".tmp
    perl -i -0777 -p -e 's{<a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail=".*?">\[email&#160;protected\]</a>}{user\@host}g' "$3".tmp
    mv "$3".tmp "$3"
}

download_it "FAQ" "$faq" "$srcdir"/docs/faq.html
download_it "Startup How-To" "$howto" "$srcdir"/docs/startup-HOWTO.html

# .html -> .txt with lynx or elinks
echo "Documentation: html -> txt..."

cat "$srcdir"/docs/faq.html \
    | LC_ALL=en_IE.utf8 $converter \
    | perl -pe '
	s/^ *//;
	if ($_ eq "\n" && $state eq "Q") { $_ = ""; }
	elsif (/^([QA]):/) { $state = $1 }
	elsif ($_ ne "\n") { $_ = "   $_"; };
' > "$srcdir"/docs/faq.txt

cat "$srcdir"/docs/startup-HOWTO.html \
    | perl -pe "s/\\bhref=([\"\'])#.*?\\1//" \
    | LC_ALL=en_IE.utf8 $converter > "$srcdir"/docs/startup-HOWTO.txt
