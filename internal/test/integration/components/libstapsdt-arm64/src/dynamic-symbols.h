#ifndef _DYNAMIC_SYMBOLS_
#define _DYNAMIC_SYMBOLS_

#include "string-table.h"
#include <libelf.h>

typedef struct {
  StringTableNode *string;
  Elf64_Sym *symbol;
} DynamicSymbol;

typedef struct DynamicSymbolList_ {
  DynamicSymbol symbol;
  struct DynamicSymbolList_ *next;
} DynamicSymbolList;

typedef struct {
  StringTable *stringTable;

  DynamicSymbol bssStart;
  DynamicSymbol eData;
  DynamicSymbol end;

  size_t count;
  DynamicSymbolList *symbols;
} DynamicSymbolTable;

DynamicSymbolTable *dynamicSymbolTableInit(StringTable *dynamicString);
DynamicSymbol *dynamicSymbolTableAdd(DynamicSymbolTable *table,
                                     char *symbolName);

void dynamicSymbolTableFree(DynamicSymbolTable *table);

#endif
