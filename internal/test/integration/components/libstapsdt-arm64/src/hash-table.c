#include "dynamic-symbols.h"
#include <stdio.h>

size_t hashTableFromSymbolTable(DynamicSymbolTable *table,
                                uint32_t **hashTable) {
  DynamicSymbolList *current;
  uint32_t nBuckets =
               table->count + 3, // + 3, to count bss, end, and eData symbols
      nChains = table->count + 3;
  size_t hashTableSize = (nBuckets + nChains + 2);

  uint32_t *hashTable_ = (uint32_t *)calloc(sizeof(uint32_t), hashTableSize);
  uint32_t *buckets = &(hashTable_[2]);
  uint32_t *chains = &(buckets[nBuckets]);
  int idx, stringIdx = 2;

  hashTable_[0] = nBuckets;
  hashTable_[1] = nChains;

  for (current = table->symbols; current != NULL; current = current->next) {
    idx = elf_hash(current->symbol.string->str) % nBuckets;
    chains[stringIdx] = buckets[idx];
    buckets[idx] = stringIdx;
    stringIdx++;
  }

  *hashTable = hashTable_;
  return hashTableSize * sizeof(uint32_t);
}
