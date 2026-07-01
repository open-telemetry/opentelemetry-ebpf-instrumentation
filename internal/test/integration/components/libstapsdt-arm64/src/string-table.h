#ifndef _STRING_TABLE_H
#define _STRING_TABLE_H

#include <stdlib.h>
#include <string.h>

typedef struct StringTableNode_ {
  int index;
  int size;
  char *str;
  struct StringTableNode_ *next;
} StringTableNode;

typedef struct {
  int count;
  size_t size;
  StringTableNode *first;
} StringTable;

StringTable *stringTableInit();

StringTableNode *stringTableAdd(StringTable *stringTable, char *str);

char *stringTableToBuffer(StringTable *stringTable);

void stringTableFree(StringTable *stringTable);

#endif
