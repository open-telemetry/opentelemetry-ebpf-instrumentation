#include <stdio.h>
#include <stdlib.h>

#include "string-table.h"

StringTable *stringTableInit() {
  StringTable *stringTable = (StringTable *)calloc(sizeof(StringTable), 1);
  stringTable->count = 1;
  stringTable->size = 1;

  stringTable->first = (StringTableNode *)calloc(sizeof(StringTableNode), 1);

  stringTable->first->index = 0;
  stringTable->first->size = 1;
  stringTable->first->str = (char *)calloc(sizeof(char), 1);
  stringTable->first->str[0] = '\0';
  stringTable->first->next = NULL;

  return stringTable;
}

StringTableNode *stringTableAdd(StringTable *stringTable, char *str) {
  StringTableNode *current;

  for (current = stringTable->first; current->next != NULL;
       current = current->next) {
  }

  current->next = (StringTableNode *)calloc(sizeof(StringTableNode), 1);
  current->next->index = current->index + current->size;

  current = current->next;
  current->size = strlen(str) + 1;

  current->str = (char *)calloc(current->size, 1);
  memcpy(current->str, str, current->size);
  current->next = NULL;

  stringTable->count += 1;
  stringTable->size += current->size;

  return current;
}

char *stringTableToBuffer(StringTable *stringTable) {
  int offset;
  StringTableNode *current;
  char *buffer = (char *)calloc(stringTable->size, 1);

  for (current = stringTable->first, offset = 0; current != NULL;
       offset += current->size, current = current->next) {
    memcpy(&buffer[offset], current->str, current->size);
  }

  return buffer;
}

void stringTableFree(StringTable *table) {
  StringTableNode *node = NULL, *next = NULL;
  for (node = table->first; node != NULL; node = next) {
    free(node->str);

    next = node->next;
    free(node);
  }
  free(table);
}
