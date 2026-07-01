#ifndef _SDT_NOTE_H
#define _SDT_NOTE_H

#include "libstapsdt.h"
#include <libelf.h>

#define NT_STAPSDT 3
#define NT_STAPSDT_NAME "stapsdt"

typedef struct SDTNote_ {
  // Header
  Elf64_Nhdr header;
  // Note name
  char *name;
  struct {
    // Note description
    Elf64_Xword probePC;
    Elf64_Xword base_addr;
    Elf64_Xword sem_addr;
    char *provider; // mainer
    char *probe;    //
    char *argFmt;   // \0
  } content;
  unsigned long long textSectionOffset;
} SDTNote;

typedef struct SDTNoteList_ {
  SDTNote *note;
  struct SDTNoteList_ *next;
} SDTNoteList_t;

size_t sdtNoteSize(SDTNote *sdt);

SDTNote *sdtNoteInit(SDTProbe_t *probe);

void sdtNoteFree(SDTNote *sdtNote);

SDTNoteList_t *sdtNoteListAppend(SDTNoteList_t *list, SDTNote *note);

size_t sdtNoteListSize(SDTNoteList_t *list);

size_t sdtNoteListToBuffer(SDTNoteList_t *list, char *buffer);

void sdtNoteListFree(SDTNoteList_t *list);

#endif
