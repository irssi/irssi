void irc_core_init(void);
void irc_core_deinit(void);

void dcc_init(void);
void dcc_deinit(void);

void flood_init(void);
void flood_deinit(void);

void notifylist_init(void);
void notifylist_deinit(void);

void irc_init(void)
{
	irc_core_init();
	dcc_init();
	flood_init();
	notifylist_init();
}

void irc_deinit(void)
{
	notifylist_deinit();
	flood_deinit();
	dcc_deinit();
	irc_core_deinit();
}
