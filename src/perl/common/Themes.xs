
MODULE = Irssi  PACKAGE = Irssi

void
theme_register(formats)
	SV *formats
PREINIT:
	AV *av;
	FORMAT_REC *formatrecs;
	char *key, *value;
	int len, n, fpos;
CODE:

        if (!SvROK(formats))
        	croak("formats is not a reference to list");
	av = (AV *) SvRV(formats);
	len = av_len(av)+1;
	if (len == 0 || (len & 1) != 0)
        	croak("formats list is invalid - not dividable by 3 (%d)", len);

	formatrecs = g_new0(FORMAT_REC, len/2+2);
	formatrecs[0].tag = g_strdup(perl_get_package());
	formatrecs[0].def = g_strdup("Perl script");

        for (fpos = 1, n = 0; n < len; n++, fpos++) {
		key = SvPV(*av_fetch(av, n, 0), PL_na); n++;
		value = SvPV(*av_fetch(av, n, 0), PL_na);

		formatrecs[fpos].tag = g_strdup(key);
		formatrecs[fpos].def = g_strdup(value);
		formatrecs[fpos].params = MAX_FORMAT_PARAMS;
	}

	theme_register_module(perl_get_package(), formatrecs);

void
printformat(level, format, ...)
	int level
	char *format
PREINIT:
	TEXT_DEST_REC dest;
	char *arglist[MAX_FORMAT_PARAMS];
	int n;
CODE:
	format_create_dest(&dest, NULL, NULL, level, NULL);
	memset(arglist, 0, sizeof(arglist));
	for (n = 2; n < 2+MAX_FORMAT_PARAMS; n++) {
		arglist[n-2] = n < items ? SvPV(ST(n), PL_na) : "";
	}

        printformat_perl(&dest, format, arglist);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server
#*******************************

void
printformat(server, target, level, format, ...)
	Irssi::Server server
	char *target
	int level
	char *format
PREINIT:
	TEXT_DEST_REC dest;
	char *arglist[MAX_FORMAT_PARAMS];
	int n;
CODE:
	format_create_dest(&dest, server, target, level, NULL);
	memset(arglist, 0, sizeof(arglist));
	for (n = 4; n < 4+MAX_FORMAT_PARAMS; n++) {
		arglist[n-4] = n < items ? SvPV(ST(n), PL_na) : "";
	}

        printformat_perl(&dest, format, arglist);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Window
#*******************************

void
printformat(window, level, format, ...)
	Irssi::Window window
	int level
	char *format
PREINIT:
	TEXT_DEST_REC dest;
	char *arglist[MAX_FORMAT_PARAMS];
	int n;
CODE:
	format_create_dest(&dest, NULL, NULL, level, window);
	memset(arglist, 0, sizeof(arglist));
	for (n = 3; n < 3+MAX_FORMAT_PARAMS; n++) {
		arglist[n-3] = n < items ? SvPV(ST(n), PL_na) : "";
	}

        printformat_perl(&dest, format, arglist);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Windowitem
#*******************************

void
printformat(item, level, format, ...)
	Irssi::Windowitem item
	int level
	char *format
PREINIT:
	TEXT_DEST_REC dest;
	char *arglist[MAX_FORMAT_PARAMS];
	int n;
CODE:
	format_create_dest(&dest, item->server, item->name, level, NULL);
	memset(arglist, 0, sizeof(arglist));
	for (n = 3; n < 3+MAX_FORMAT_PARAMS; n++) {
		arglist[n-3] = n < items ? SvPV(ST(n), PL_na) : "";
	}

        printformat_perl(&dest, format, arglist);

