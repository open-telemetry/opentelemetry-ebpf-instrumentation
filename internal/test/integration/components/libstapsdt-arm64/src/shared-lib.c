#include "shared-lib.h"
#include "hash-table.h"
#include <stdio.h>

#define PHDR_ALIGN 0x200000

void _funcStart();
void _funcEnd();

uint32_t eh_frame[] = {0x0, 0x0};

Elf *createElf(int fd) {
  Elf *e;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    // TODO (mmarchini) error message
    return NULL;
  }

  if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL) {
    // TODO (mmarchini) error message
    return NULL;
  }

  return e;
}

int createElfStringTables(DynElf *dynElf) {
  // FIXME (mmarchini) error handling
  dynElf->stringTable = stringTableInit();
  dynElf->dynamicString = stringTableInit();
  dynElf->dynamicSymbols = dynamicSymbolTableInit(dynElf->dynamicString);
  return 0;
}

Elf64_Ehdr *createElfHeader(Elf *elf) {
  Elf64_Ehdr *ehdr;
  if ((ehdr = elf64_newehdr(elf)) == NULL) {
    // FIXME (mmarchini) properly free everything
    return NULL;
  }

  ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr->e_type = ET_DYN;
#if defined(__aarch64__)
  ehdr->e_machine = EM_AARCH64;
#else
  ehdr->e_machine = EM_X86_64;
#endif
  ehdr->e_version = EV_CURRENT;
  ehdr->e_flags = 0;

  return ehdr;
}

int createElfProgramHeaders(DynElf *dynElf) {
  if ((dynElf->phdrLoad1 = elf64_newphdr(dynElf->elf, 4)) == NULL) {
    // TODO (mmarchini) error message
    // FIXME (mmarchini) properly free everything
    return -1;
  }

  dynElf->phdrDyn = &dynElf->phdrLoad1[2];
  dynElf->phdrLoad2 = &dynElf->phdrLoad1[1];
  dynElf->phdrStack = &dynElf->phdrLoad1[3];

  return 0;
}

int createElfSections(DynElf *dynElf) {
  // FIXME (mmarchini) error message
  dynElf->sections.shStrTab =
      sectionInit(dynElf->elf, dynElf->stringTable, ".shstrtab");
  dynElf->sections.hash =
      sectionInit(dynElf->elf, dynElf->stringTable, ".hash");
  dynElf->sections.dynSym =
      sectionInit(dynElf->elf, dynElf->stringTable, ".dynsym");
  dynElf->sections.dynStr =
      sectionInit(dynElf->elf, dynElf->stringTable, ".dynstr");
  dynElf->sections.text =
      sectionInit(dynElf->elf, dynElf->stringTable, ".text");
  dynElf->sections.ehFrame =
      sectionInit(dynElf->elf, dynElf->stringTable, ".eh_frame");
  dynElf->sections.dynamic =
      sectionInit(dynElf->elf, dynElf->stringTable, ".dynamic");
  dynElf->sections.sdtBase =
      sectionInit(dynElf->elf, dynElf->stringTable, ".stapsdt.base");
  dynElf->sections.sdtNote =
      sectionInit(dynElf->elf, dynElf->stringTable, ".note.stapsdt");

  return 0;
}

void *createDynSymData(DynamicSymbolTable *table) {
  size_t symbolsCount = (5 + table->count);
  int i;
  DynamicSymbolList *current;
  Elf64_Sym *dynsyms = calloc(sizeof(Elf64_Sym), (5 + table->count));

  for (i = 0; i < symbolsCount; i++) {
    dynsyms[i].st_name = 0;
    dynsyms[i].st_info = 0;
    dynsyms[i].st_other = 0;
    dynsyms[i].st_shndx = 0;
    dynsyms[i].st_value = 0;
    dynsyms[i].st_size = 0;
  }

  dynsyms[1].st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);

  current = table->symbols;
  for (i = 0; i < table->count; i++) {
    dynsyms[i + 2].st_name = current->symbol.string->index;
    dynsyms[i + 2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    current = current->next;
  }
  i -= 1;

  dynsyms[i + 3].st_name = table->bssStart.string->index;
  dynsyms[i + 3].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);

  dynsyms[i + 4].st_name = table->eData.string->index;
  dynsyms[i + 4].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);

  dynsyms[i + 5].st_name = table->end.string->index;
  dynsyms[i + 5].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);

  return dynsyms;
}

// TODO(mmarchini): dynamic strings creation
void *createDynamicData() {
  Elf64_Dyn *dyns = calloc(sizeof(Elf64_Dyn), 11);

  for (int i = 0; i < 11; i++) {
    dyns[i].d_tag = DT_NULL;
  }

  dyns[0].d_tag = DT_HASH;
  dyns[1].d_tag = DT_STRTAB;
  dyns[2].d_tag = DT_SYMTAB;
  dyns[3].d_tag = DT_STRSZ;

  return dyns;
}

DynElf *dynElfInit(int fd) {
  DynElf *dynElf = (DynElf *)calloc(sizeof(DynElf), 1);
  dynElf->sdtNotes = NULL;
  dynElf->sdtNotesCount = 0;

  if (createElfStringTables(dynElf) == -1) {
    // TODO (mmarchini) error message
    // FIXME (mmarchini) properly free everything
    free(dynElf);
    return NULL;
  }

  dynElf->elf = createElf(fd);

  if ((dynElf->ehdr = createElfHeader(dynElf->elf)) == NULL) {
    // TODO (mmarchini) error message
    // FIXME (mmarchini) properly free everything
    free(dynElf);
    return NULL;
  }

  if (createElfProgramHeaders(dynElf) == -1) {
    // TODO (mmarchini) error message
    // FIXME (mmarchini) properly free everything
    free(dynElf);
    return NULL;
  }

  if (createElfSections(dynElf) == -1) {
    // TODO (mmarchini) error message
    // FIXME (mmarchini) properly free everything
    free(dynElf);
    return NULL;
  }

  return dynElf;
}

int dynElfAddProbe(DynElf *dynElf, SDTProbe_t *probe) {
  dynElf->sdtNotes = sdtNoteListAppend(dynElf->sdtNotes, sdtNoteInit(probe));
  dynamicSymbolTableAdd(dynElf->dynamicSymbols, probe->name);
  dynElf->sdtNotesCount++;

  return 0;
}

size_t prepareTextData(DynElf *dynElf, char **textData) {
  size_t funcSize =
      (unsigned long long)_funcEnd - (unsigned long long)_funcStart;
  unsigned long long offset = 0;
  *textData = calloc(funcSize, dynElf->sdtNotesCount);

  for (SDTNoteList_t *node = dynElf->sdtNotes; node != NULL;
       node = node->next) {
    node->note->textSectionOffset = offset;
    memcpy(&((*textData)[offset]), _funcStart, funcSize);
    offset += funcSize;
  }

  return offset;
}

// TODO (mmarchini) refactor (no idea how)
int dynElfSave(DynElf *dynElf) {
  Elf64_Sym *dynSymData = createDynSymData(dynElf->dynamicSymbols);
  Elf64_Dyn *dynamicData = createDynamicData();
  void *sdtNoteData = calloc(sdtNoteListSize(dynElf->sdtNotes), 1);
  void *stringTableData = stringTableToBuffer(dynElf->stringTable),
       *dynamicStringData = stringTableToBuffer(dynElf->dynamicString);
  void *textData = NULL;
  uint32_t *hashTable;
  size_t hashTableSize =
      hashTableFromSymbolTable(dynElf->dynamicSymbols, &hashTable);
  int i;

  // ----------------------------------------------------------------------- //
  // Section: HASH

  dynElf->sections.hash->data->d_align = 8;
  dynElf->sections.hash->data->d_off = 0LL;
  dynElf->sections.hash->data->d_buf = hashTable;
  dynElf->sections.hash->data->d_type = ELF_T_XWORD;
  dynElf->sections.hash->data->d_size = hashTableSize;
  dynElf->sections.hash->data->d_version = EV_CURRENT;

  dynElf->sections.hash->shdr->sh_name = dynElf->sections.hash->string->index;
  dynElf->sections.hash->shdr->sh_type = SHT_HASH;
  dynElf->sections.hash->shdr->sh_flags = SHF_ALLOC;

  // ----------------------------------------------------------------------- //
  // Section: Dynsym

  dynElf->sections.dynSym->data->d_align = 8;
  dynElf->sections.dynSym->data->d_off = 0LL;
  dynElf->sections.dynSym->data->d_buf = dynSymData;
  dynElf->sections.dynSym->data->d_type = ELF_T_XWORD;
  dynElf->sections.dynSym->data->d_size =
      sizeof(Elf64_Sym) * ((5 + dynElf->dynamicSymbols->count));
  dynElf->sections.dynSym->data->d_version = EV_CURRENT;

  dynElf->sections.dynSym->shdr->sh_name =
      dynElf->sections.dynSym->string->index;
  dynElf->sections.dynSym->shdr->sh_type = SHT_DYNSYM;
  dynElf->sections.dynSym->shdr->sh_flags = SHF_ALLOC;
  dynElf->sections.dynSym->shdr->sh_info = 2; // First non local symbol

  dynElf->sections.hash->shdr->sh_link =
      elf_ndxscn(dynElf->sections.dynSym->scn);

  // ----------------------------------------------------------------------- //
  // Section: DYNSTR

  dynElf->sections.dynStr->data->d_align = 1;
  dynElf->sections.dynStr->data->d_off = 0LL;
  dynElf->sections.dynStr->data->d_buf = dynamicStringData;

  dynElf->sections.dynStr->data->d_type = ELF_T_BYTE;
  dynElf->sections.dynStr->data->d_size = dynElf->dynamicString->size;
  dynElf->sections.dynStr->data->d_version = EV_CURRENT;

  dynElf->sections.dynStr->shdr->sh_name =
      dynElf->sections.dynStr->string->index;
  dynElf->sections.dynStr->shdr->sh_type = SHT_STRTAB;
  dynElf->sections.dynStr->shdr->sh_flags = SHF_ALLOC;

  dynElf->sections.dynSym->shdr->sh_link =
      elf_ndxscn(dynElf->sections.dynStr->scn);

  // ----------------------------------------------------------------------- //
  // Section: TEXT

  dynElf->sections.text->data->d_align = 16;
  dynElf->sections.text->data->d_off = 0LL;
  dynElf->sections.text->data->d_size =
      prepareTextData(dynElf, (char **)&textData);
  dynElf->sections.text->data->d_buf = textData;
  dynElf->sections.text->data->d_type = ELF_T_BYTE;
  dynElf->sections.text->data->d_version = EV_CURRENT;

  dynElf->sections.text->shdr->sh_name = dynElf->sections.text->string->index;
  dynElf->sections.text->shdr->sh_type = SHT_PROGBITS;
  dynElf->sections.text->shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;

  // ----------------------------------------------------------------------- //
  // Section: SDT BASE

  dynElf->sections.sdtBase->data->d_align = 1;
  dynElf->sections.sdtBase->data->d_off = 0LL;
  dynElf->sections.sdtBase->data->d_buf = eh_frame;
  dynElf->sections.sdtBase->data->d_type = ELF_T_BYTE;
  dynElf->sections.sdtBase->data->d_size = 1;
  dynElf->sections.sdtBase->data->d_version = EV_CURRENT;

  dynElf->sections.sdtBase->shdr->sh_name =
      dynElf->sections.sdtBase->string->index;
  dynElf->sections.sdtBase->shdr->sh_type = SHT_PROGBITS;
  dynElf->sections.sdtBase->shdr->sh_flags = SHF_ALLOC;

  // ----------------------------------------------------------------------- //
  // Section: EH_FRAME

  dynElf->sections.ehFrame->data->d_align = 8;
  dynElf->sections.ehFrame->data->d_off = 0LL;
  dynElf->sections.ehFrame->data->d_buf = eh_frame;
  dynElf->sections.ehFrame->data->d_type = ELF_T_BYTE;
  dynElf->sections.ehFrame->data->d_size = 0;
  dynElf->sections.ehFrame->data->d_version = EV_CURRENT;

  dynElf->sections.ehFrame->shdr->sh_name =
      dynElf->sections.ehFrame->string->index;
  dynElf->sections.ehFrame->shdr->sh_type = SHT_PROGBITS;
  dynElf->sections.ehFrame->shdr->sh_flags = SHF_ALLOC;

  // ----------------------------------------------------------------------- //
  // Section: DYNAMIC

  dynElf->sections.dynamic->data->d_align = 8;
  dynElf->sections.dynamic->data->d_off = 0LL;
  dynElf->sections.dynamic->data->d_buf = dynamicData;
  dynElf->sections.dynamic->data->d_type = ELF_T_BYTE;
  dynElf->sections.dynamic->data->d_size = 11 * sizeof(Elf64_Dyn);
  dynElf->sections.dynamic->data->d_version = EV_CURRENT;

  dynElf->sections.dynamic->shdr->sh_name =
      dynElf->sections.dynamic->string->index;
  dynElf->sections.dynamic->shdr->sh_type = SHT_DYNAMIC;
  dynElf->sections.dynamic->shdr->sh_flags = SHF_WRITE | SHF_ALLOC;
  dynElf->sections.dynamic->shdr->sh_link =
      elf_ndxscn(dynElf->sections.dynStr->scn);

  // ----------------------------------------------------------------------- //
  // Section: SDT_NOTE

  dynElf->sections.sdtNote->data->d_align = 4;
  dynElf->sections.sdtNote->data->d_off = 0LL;
  dynElf->sections.sdtNote->data->d_buf = sdtNoteData;
  dynElf->sections.sdtNote->data->d_type = ELF_T_NHDR;
  dynElf->sections.sdtNote->data->d_size = sdtNoteListSize(dynElf->sdtNotes);
  dynElf->sections.sdtNote->data->d_version = EV_CURRENT;

  dynElf->sections.sdtNote->shdr->sh_name =
      dynElf->sections.sdtNote->string->index;
  dynElf->sections.sdtNote->shdr->sh_type = SHT_NOTE;
  dynElf->sections.sdtNote->shdr->sh_flags = 0;

  // ----------------------------------------------------------------------- //
  // Section: SHSTRTAB

  dynElf->sections.shStrTab->data->d_align = 1;
  dynElf->sections.shStrTab->data->d_off = 0LL;
  dynElf->sections.shStrTab->data->d_buf = stringTableData;
  dynElf->sections.shStrTab->data->d_type = ELF_T_BYTE;
  dynElf->sections.shStrTab->data->d_size = dynElf->stringTable->size;
  dynElf->sections.shStrTab->data->d_version = EV_CURRENT;

  dynElf->sections.shStrTab->shdr->sh_name =
      dynElf->sections.shStrTab->string->index;
  dynElf->sections.shStrTab->shdr->sh_type = SHT_STRTAB;
  dynElf->sections.shStrTab->shdr->sh_flags = 0;

  dynElf->ehdr->e_shstrndx = elf_ndxscn(dynElf->sections.shStrTab->scn);

  // ----------------------------------------------------------------------- //

  if (elf_update(dynElf->elf, ELF_C_NULL) < 0) {
    return -1;
  }

  dynElf->sections.hash->shdr->sh_addr = dynElf->sections.hash->shdr->sh_offset;
  dynElf->sections.hash->offset = dynElf->sections.hash->shdr->sh_offset;

  // -- //

  dynElf->sections.dynSym->shdr->sh_addr =
      dynElf->sections.dynSym->shdr->sh_offset;
  dynElf->sections.dynSym->offset = dynElf->sections.dynSym->shdr->sh_offset;

  // -- //

  dynElf->sections.dynStr->shdr->sh_addr =
      dynElf->sections.dynStr->shdr->sh_offset;
  dynElf->sections.dynStr->offset = dynElf->sections.dynStr->shdr->sh_offset;

  // -- //

  dynElf->sections.text->shdr->sh_addr = dynElf->sections.text->shdr->sh_offset;
  dynElf->ehdr->e_entry = dynElf->sections.text->shdr->sh_addr;
  dynElf->sections.text->offset = dynElf->sections.text->shdr->sh_offset;

  // -- //

  dynElf->sections.sdtBase->shdr->sh_addr =
      dynElf->sections.sdtBase->shdr->sh_offset;
  dynElf->sections.sdtBase->offset = dynElf->sections.sdtBase->shdr->sh_offset;

  // -- //

  dynElf->sections.ehFrame->shdr->sh_addr =
      dynElf->sections.ehFrame->shdr->sh_offset;
  dynElf->sections.ehFrame->offset = dynElf->sections.ehFrame->shdr->sh_offset;

  // -- //

  dynElf->sections.dynamic->shdr->sh_addr =
      PHDR_ALIGN + dynElf->sections.dynamic->shdr->sh_offset;
  dynElf->sections.dynamic->offset = dynElf->sections.dynamic->shdr->sh_offset;

  // -- //

  dynElf->sections.sdtNote->shdr->sh_addr =
      dynElf->sections.sdtNote->shdr->sh_offset;
  dynElf->sections.sdtNote->offset = dynElf->sections.sdtNote->shdr->sh_offset;

  for (SDTNoteList_t *node = dynElf->sdtNotes; node != NULL;
       node = node->next) {
    node->note->content.probePC =
        dynElf->sections.text->offset + node->note->textSectionOffset;
    node->note->content.base_addr = dynElf->sections.sdtBase->offset;
  }
  sdtNoteListToBuffer(dynElf->sdtNotes, sdtNoteData);

  // -- //

  dynElf->sections.shStrTab->offset =
      dynElf->sections.shStrTab->shdr->sh_offset;

  // -- //

  // ----------------------------------------------------------------------- //

  if (elf_update(dynElf->elf, ELF_C_NULL) < 0) {
    return -1;
  }

  // ----------------------------------------------------------------------- //
  // Fill PHDRs

  // First LOAD PHDR

  dynElf->phdrLoad1->p_type = PT_LOAD;
  dynElf->phdrLoad1->p_flags = PF_X + PF_R;
  dynElf->phdrLoad1->p_offset = 0;
  dynElf->phdrLoad1->p_vaddr = 0;
  dynElf->phdrLoad1->p_paddr = 0;
  dynElf->phdrLoad1->p_filesz = dynElf->sections.ehFrame->offset;
  dynElf->phdrLoad1->p_memsz = dynElf->sections.ehFrame->offset;
  dynElf->phdrLoad1->p_align = PHDR_ALIGN;

  // Second LOAD PHDR

  dynElf->phdrLoad2->p_type = PT_LOAD;
  dynElf->phdrLoad2->p_flags = PF_W + PF_R;
  dynElf->phdrLoad2->p_offset = dynElf->sections.ehFrame->offset;
  dynElf->phdrLoad2->p_vaddr = dynElf->sections.ehFrame->offset + PHDR_ALIGN;
  dynElf->phdrLoad2->p_paddr = dynElf->sections.ehFrame->offset + PHDR_ALIGN;
  dynElf->phdrLoad2->p_filesz = dynElf->sections.dynamic->data->d_size;
  dynElf->phdrLoad2->p_memsz = dynElf->sections.dynamic->data->d_size;
  dynElf->phdrLoad2->p_align = PHDR_ALIGN;

  // Dynamic PHDR

  dynElf->phdrDyn->p_type = PT_DYNAMIC;
  dynElf->phdrDyn->p_flags = PF_W + PF_R;
  dynElf->phdrDyn->p_offset = dynElf->sections.ehFrame->offset;
  dynElf->phdrDyn->p_vaddr = dynElf->sections.ehFrame->offset + PHDR_ALIGN;
  dynElf->phdrDyn->p_paddr = dynElf->sections.ehFrame->offset + PHDR_ALIGN;
  dynElf->phdrDyn->p_filesz = dynElf->sections.dynamic->data->d_size;
  dynElf->phdrDyn->p_memsz = dynElf->sections.dynamic->data->d_size;
  dynElf->phdrDyn->p_align = 0x8; // XXX magic number?

  // GNU_STACK PHDR
  dynElf->phdrStack->p_type = PT_GNU_STACK;
  dynElf->phdrStack->p_flags = PF_W + PF_R;
  dynElf->phdrStack->p_offset = 0;
  dynElf->phdrStack->p_vaddr = 0;
  dynElf->phdrStack->p_paddr = 0;
  dynElf->phdrStack->p_filesz = 0;
  dynElf->phdrStack->p_memsz = 0;
  dynElf->phdrStack->p_align = 0x10;

  // Fix offsets DynSym
  // ----------------------------------------------------------------------- //

  dynSymData[0].st_value = 0;

  dynSymData[1].st_value = dynElf->sections.text->offset;
  dynSymData[1].st_shndx = elf_ndxscn(dynElf->sections.text->scn);

  i = 0;
  for (SDTNoteList_t *node = dynElf->sdtNotes; node != NULL;
       node = node->next) {
    dynSymData[i + 2].st_value =
        dynElf->sections.text->offset + node->note->textSectionOffset;
    dynSymData[i + 2].st_shndx = elf_ndxscn(dynElf->sections.text->scn);
    i++;
  }
  i -= 1;

  dynSymData[i + 3].st_value = PHDR_ALIGN + dynElf->sections.shStrTab->offset;
  dynSymData[i + 3].st_shndx = elf_ndxscn(dynElf->sections.dynamic->scn);

  dynSymData[i + 4].st_value = PHDR_ALIGN + dynElf->sections.shStrTab->offset;
  dynSymData[i + 4].st_shndx = elf_ndxscn(dynElf->sections.dynamic->scn);

  dynSymData[i + 5].st_value = PHDR_ALIGN + dynElf->sections.shStrTab->offset;
  dynSymData[i + 5].st_shndx = elf_ndxscn(dynElf->sections.dynamic->scn);

  // Fix offsets Dynamic
  // ----------------------------------------------------------------------- //

  dynamicData[0].d_un.d_ptr = dynElf->sections.hash->offset;
  dynamicData[1].d_un.d_ptr = dynElf->sections.dynStr->offset;
  dynamicData[2].d_un.d_ptr = dynElf->sections.dynSym->offset;
  dynamicData[3].d_un.d_val = dynElf->dynamicString->size;
  dynamicData[4].d_un.d_val = sizeof(Elf64_Sym);

  // ----------------------------------------------------------------------- //

  elf_flagphdr(dynElf->elf, ELF_C_SET, ELF_F_DIRTY);

  if (elf_update(dynElf->elf, ELF_C_WRITE) < 0) {
    return -1;
  }

  free(textData);
  free(dynSymData);
  free(dynamicData);
  free(sdtNoteData);
  free(stringTableData);
  free(dynamicStringData);
  free(hashTable);
  return 0;
}

void dynElfSectionsClose(SectionsList *sections) {
  if (sections->hash != NULL) {
    sectionFree(sections->hash);
  }

  if (sections->dynSym != NULL) {
    sectionFree(sections->dynSym);
  }

  if (sections->dynStr != NULL) {
    sectionFree(sections->dynStr);
  }

  if (sections->text != NULL) {
    sectionFree(sections->text);
  }

  if (sections->sdtBase != NULL) {
    sectionFree(sections->sdtBase);
  }

  if (sections->ehFrame != NULL) {
    sectionFree(sections->ehFrame);
  }

  if (sections->dynamic != NULL) {
    sectionFree(sections->dynamic);
  }

  if (sections->sdtNote != NULL) {
    sectionFree(sections->sdtNote);
  }

  if (sections->shStrTab != NULL) {
    sectionFree(sections->shStrTab);
  }
}

void dynElfClose(DynElf *dynElf) {
  if (dynElf->stringTable != NULL) {
    stringTableFree(dynElf->stringTable);
  }

  if (dynElf->dynamicString != NULL) {
    stringTableFree(dynElf->dynamicString);
  }

  if (dynElf->dynamicSymbols != NULL) {
    dynamicSymbolTableFree(dynElf->dynamicSymbols);
  }

  if (dynElf->sdtNotes != NULL) {
    sdtNoteListFree(dynElf->sdtNotes);
  }

  dynElfSectionsClose(&dynElf->sections);

  (void)elf_end(dynElf->elf);
  free(dynElf);
}
