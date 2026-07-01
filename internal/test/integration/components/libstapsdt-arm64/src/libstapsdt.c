#include <dlfcn.h>
#include <err.h>
#include <libelf.h>
#include <limits.h>
#include <linux/version.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "dynamic-symbols.h"
#include "errors.h"
#include "libstapsdt.h"
#include "sdtnote.h"
#include "section.h"
#include "shared-lib.h"
#include "string-table.h"
#include "util.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
#include <linux/fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifdef __NR_memfd_create // older glibc may not have this syscall defined
#define HAVE_LIBSTAPSDT_MEMORY_BACKED_FD
// Note that linux must be 3.17 or greater to support this
static inline int memfd_create(const char *name, unsigned int flags) {
  return syscall(__NR_memfd_create, name, flags);
}
#endif // #ifdef __NR_memfd_create
#endif // if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)

int createSharedLibrary(int fd, SDTProvider_t *provider) {
  DynElf *dynElf = dynElfInit(fd);

  for (SDTProbeList_t *node = provider->probes; node != NULL;
       node = node->next) {
    dynElfAddProbe(dynElf, &(node->probe));
  }

  if (dynElfSave(dynElf) == -1) {
    sdtSetError(provider, elfCreationError, provider->name);
    return -1;
  }

  dynElfClose(dynElf);

  return 0;
}

SDTProvider_t *providerInit(const char *name) {
  SDTProvider_t *provider = (SDTProvider_t *)calloc(sizeof(SDTProvider_t), 1);
  provider->error = NULL;
  provider->errno = noError;
  provider->probes = NULL;
  provider->_handle = NULL;
  provider->_filename = NULL;

  provider->_memfd = -1;
#ifdef HAVE_LIBSTAPSDT_MEMORY_BACKED_FD
  provider->_use_memfd = memfd_enabled;
#else
  provider->_use_memfd = memfd_disabled;
#endif

  provider->name = (char *)calloc(sizeof(char), strlen(name) + 1);
  memcpy(provider->name, name, sizeof(char) * strlen(name) + 1);

  return provider;
}

int providerUseMemfd(SDTProvider_t *provider, const MemFDOption_t use_memfd) {
#ifdef HAVE_LIBSTAPSDT_MEMORY_BACKED_FD
  // Changing use of memfd must be done while provider is not loaded.
  if (provider && !provider->_handle) {
    provider->_use_memfd = use_memfd;
    return 1;
  }
#endif
  return 0;
}

SDTProbe_t *providerAddProbe(SDTProvider_t *provider, const char *name,
                             int argCount, ...) {
  int i;
  va_list vl;
  ArgType_t arg;
  va_start(vl, argCount);

  SDTProbeList_t *probeList =
      (SDTProbeList_t *)calloc(sizeof(SDTProbeList_t), 1);
  probeList->probe._fire = NULL;

  probeList->probe.name = (char *)calloc(sizeof(char), strlen(name) + 1);
  memcpy(probeList->probe.name, name, sizeof(char) * strlen(name) + 1);

  probeList->next = provider->probes;
  provider->probes = probeList;

  probeList->probe.argCount = argCount;

  for (i = 0; i < argCount; i++) {
    arg = va_arg(vl, ArgType_t);
    probeList->probe.argFmt[i] = arg;
  }

  for (; i < MAX_ARGUMENTS; i++) {
    probeList->probe.argFmt[i] = noarg;
  }

  probeList->probe.provider = provider;

  return &(probeList->probe);
}

static char *tempElfPath(int *fd, const char *name, const int use_memfd) {
  char *filename = NULL;
#ifdef HAVE_LIBSTAPSDT_MEMORY_BACKED_FD
  if (use_memfd == memfd_enabled) {
    char path_buffer[PATH_MAX];
    snprintf(path_buffer, sizeof(path_buffer), "libstapsdt:%s", name);

    *fd = memfd_create(path_buffer, F_SEAL_SEAL);
    if (*fd < 0) {
      return NULL;
    }

    snprintf(path_buffer, sizeof(path_buffer), "/proc/%d/fd/%d", getpid(), *fd);
    filename = calloc(sizeof(char), strlen(path_buffer) + 1);
    strncpy(filename, path_buffer, strlen(path_buffer) + 1);

    return filename;
  }
#endif
  filename = calloc(sizeof(char), strlen("/tmp/-XXXXXX.so") + strlen(name) + 1);

  sprintf(filename, "/tmp/%s-XXXXXX.so", name);

  if ((*fd = mkstemps(filename, 3)) < 0) {
    free(filename);
    return NULL;
  }
  return filename;
}

int providerLoad(SDTProvider_t *provider) {
  int fd;
  void *fireProbe;
  char *error;

  provider->_filename = tempElfPath(&fd, provider->name, provider->_use_memfd);
  if (provider->_use_memfd == memfd_enabled) {
    provider->_memfd = fd;
  }
  if (provider->_filename == NULL) {
    sdtSetError(provider, tmpCreationError);
    return -1;
  }

  if (createSharedLibrary(fd, provider) != 0) {
    (void)close(fd);
    return -1;
  }

  if (provider->_memfd == -1) {
    (void)close(fd);
  }

  provider->_handle = dlopen(provider->_filename, RTLD_LAZY);
  if (!provider->_handle) {
    sdtSetError(provider, sharedLibraryOpenError, provider->_filename,
                dlerror());
    return -1;
  }

  for (SDTProbeList_t *node = provider->probes; node != NULL;
       node = node->next) {
    fireProbe = dlsym(provider->_handle, node->probe.name);

    // TODO (mmarchini) handle errors better when a symbol fails to load
    if ((error = dlerror()) != NULL) {
      sdtSetError(provider, sharedLibraryOpenError, provider->_filename,
                  node->probe.name, error);
      return -1;
    }

    node->probe._fire = fireProbe;
  }

  return 0;
}

int providerUnload(SDTProvider_t *provider) {
  if (provider->_handle == NULL) {
    return 0;
  }
  if (dlclose(provider->_handle) != 0) {
    sdtSetError(provider, sharedLibraryCloseError, provider->_filename,
                provider->name, dlerror());
    return -1;
  }
  provider->_handle = NULL;

  for (SDTProbeList_t *node = provider->probes; node != NULL;
       node = node->next) {
    node->probe._fire = NULL;
  }

  if (provider->_memfd > 0) {
    (void)close(provider->_memfd);
    provider->_memfd = -1;
  } else {
    unlink(provider->_filename);
  }
  free(provider->_filename);

  return 0;
}

void probeFire(SDTProbe_t *probe, ...) {
  if (probe->_fire == NULL) {
    return;
  }
  va_list vl;
  va_start(vl, probe);
  uint64_t arg[6] = {0};
  for (int i = 0; i < probe->argCount; i++) {
    arg[i] = va_arg(vl, uint64_t);
  }

  switch (probe->argCount) {
  case 0:
    ((void (*)())probe->_fire)();
    return;
  case 1:
    ((void (*)())probe->_fire)(arg[0]);
    return;
  case 2:
    ((void (*)())probe->_fire)(arg[0], arg[1]);
    return;
  case 3:
    ((void (*)())probe->_fire)(arg[0], arg[1], arg[2]);
    return;
  case 4:
    ((void (*)())probe->_fire)(arg[0], arg[1], arg[2], arg[3]);
    return;
  case 5:
    ((void (*)())probe->_fire)(arg[0], arg[1], arg[2], arg[3], arg[4]);
    return;
  case 6:
    ((void (*)())probe->_fire)(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
    return;
  default:
    ((void (*)())probe->_fire)();
    return;
  }
}

int probeIsEnabled(SDTProbe_t *probe) {
  if (probe->_fire == NULL) {
    return 0;
  }
  if (((*(char *)probe->_fire) & 0x90) == 0x90) {
    return 0;
  }
  return 1;
}

void providerDestroy(SDTProvider_t *provider) {
  SDTProbeList_t *node = NULL, *next = NULL;

  for (node = provider->probes; node != NULL; node = next) {
    free(node->probe.name);
    next = node->next;
    free(node);
  }
  free(provider->name);
  if (provider->error != NULL) {
    free(provider->error);
  }
  free(provider);
}
