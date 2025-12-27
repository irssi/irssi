#!/bin/sh -e
# Run this to download QNA and New-users from irssi.org

PKG_NAME="Irssi"
export LC_ALL=en_IE.utf8

site=https://irssi.org

qna=$site/documentation/qna/
howto=$site/New-users/
#design=$site/documentation/design/

# remove everything until H1 and optionally 2 DIVs before the
# FOOTER. May need to be adjusted as the source pages change
pageclean_regex='s{.*(?=<h1)}{}s;
s{(\s*<script\s.*?</script>)?\s*(</section>(\r?\n)*\s*</article>\s*)?(</div>\s*){0,3}<footer.*}{}s;
s{(<.*?)\sclass="(?:[^"]*\s+)*(?:highlighter-rouge|highlight)"(.*?>)}{\1\2}g;
s{<a class="headerlink" href=".*?" title="Permalink to this heading"></a>}{}g;
s{<span.*?>(.*?)</span>}{\1}g;'

srcdir=`dirname "$0"`
test -z "$srcdir" && srcdir=.
srcdir="$srcdir"/..

if test ! -f "$srcdir"/irssi.conf; then
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

addheadermark="perl -p -e s{<h(\\d).*?>\\K}{(q:#:x\$1).q:&#32;:}ge;s{(?=</h(\\d)>)}{q:&#32;:.(q:#:x\$1)}ge"
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

download_it_nested() {
    name=$1; shift
    src=$1; shift
    dest=$1; shift
    download_it "$name" "$src" "$dest".nest
    echo > "$dest"
    eval $(perl -n -0777 -e 'print qq{download_it "\$name ($2)" "\${src}$1/" "\${dest}.$1";
cat "\${dest}.$1" >> "\${dest}.tmp";
rm "\${dest}.$1";\n}
 while(m{<a class="reference internal" href="(.*?)/">(.*?)</a>}g)' "$dest".nest)
    rm "$dest".nest
    perl -i -0777 -p -e 's{<base href=.*?>}{}g;s{\A}{<base href='"'${src}multi/'"'>\n}' "$dest".tmp
    mv "$dest".tmp "$dest"
}

download_it_nested "QNA" "$qna" "$srcdir"/docs/qna.html
download_it "New users guide" "$howto" "$srcdir"/docs/New-users.html
#download_it "Design" "$design" "$srcdir"/docs/design.html

# .html -> .txt with lynx or elinks
echo "Documentation: html -> txt... [converter: $converter]"

cat "$srcdir"/docs/qna.html \
    | $addheadermark | $converter > "$srcdir"/docs/qna.txt

cat "$srcdir"/docs/New-users.html \
    | $addheadermark | $converter > "$srcdir"/docs/New-users.txt

#cat "$srcdir"/docs/design.html \
#    | $addheadermark | $converter > "$srcdir"/docs/design.txt
