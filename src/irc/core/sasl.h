#ifndef __SASL_H
#define __SASL_H

enum {
	SASL_MECHANISM_NONE = 0,
	SASL_MECHANISM_PLAIN,
	SASL_MECHANISM_EXTERNAL,
	SASL_MECHANISM_MAX
};

void sasl_init(void);
void sasl_deinit(void);

#endif
