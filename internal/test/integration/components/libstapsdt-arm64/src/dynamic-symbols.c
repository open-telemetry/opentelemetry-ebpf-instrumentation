#include "dynamic-symbols.h"
#include "string-table.h"
#include <libelf.h>

DynamicSymbolTable *dynamicSymbolTableInit(StringTable *dynamicString) {
  DynamicSymbolTable *dynSymTab =
      (DynamicSymbolTable *)calloc(sizeof(DynamicSymbolTable), 1);

  dynSymTab->stringTable = dynamicString;

  dynSymTab->bssStart.string = stringTableAdd(dynamicString, "__bss_start");
  dynSymTab->eData.string = stringTableAdd(dynamicString, "_edata");
  dynSymTab->end.string = stringTableAdd(dynamicString, "_end");

  dynSymTab->count = 0;
  dynSymTab->symbols = NULL;

  return dynSymTab;
}

DynamicSymbol *dynamicSymbolTableAdd(DynamicSymbolTable *table,
                                     char *symbolName) {
  DynamicSymbolList *symbol =
      (DynamicSymbolList *)calloc(sizeof(DynamicSymbolList), 1);

  symbol->symbol.string = stringTableAdd(table->stringTable, symbolName);

  symbol->next = table->symbols;
  table->symbols = symbol;
  table->count += 1;

  return &(symbol->symbol);
}

void dynamicSymbolTableFree(DynamicSymbolTable *table) {
  DynamicSymbolList *node = NULL, *next = NULL;
  for (node = table->symbols; node != NULL; node = next) {
    next = node->next;
    free(node);
  }
  free(table);
}
