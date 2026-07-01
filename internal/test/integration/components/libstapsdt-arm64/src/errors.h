#ifndef _ERRORS_H
#define _ERRORS_H

#include "libstapsdt.h"

void sdtSetError(SDTProvider_t *provider, SDTError_t error, ...);

#endif
