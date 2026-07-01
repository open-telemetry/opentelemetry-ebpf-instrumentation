#ifndef _SECTION_H
#define _SECTION_H

#include <libelf.h>

#include "string-table.h"

typedef struct {
  Elf_Scn *scn;
  Elf64_Shdr *shdr;
  Elf_Data *data;
  Elf64_Addr offset;

  StringTableNode *string;
} Section;

Section *sectionInit(Elf *e, StringTable *table, char *name);

void sectionFree(Section *section);

#endif
