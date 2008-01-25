#ifndef __ARGS_H
#define __ARGS_H

#ifdef HAVE_POPT_H
#  include <popt.h>
#else
#  include "lib-popt/popt.h"
#endif

void args_register(struct poptOption *options);
void args_execute(int argc, char *argv[]);

#endif
