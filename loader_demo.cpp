#include <cstdio>
#include <cstdint>
#include <string>

#include <capstone/capstone.h>

#include "loader.h"

int main(int argc, char *argv[]) {
    Binary bin;
#ifdef DEBUG
    Section *sec;
    Symbol *sym;
#endif
    Section *text;
    std::string fname;
    csh handle;
    cs_insn *instructions;
    cs_err e;
    size_t cnt;

    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    fname.assign(argv[1]);

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        return 1;
    }

#ifdef DEBUG
    printf("load binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
            bin.filename.c_str(), bin.type_str.c_str(),
            bin.arch_str.c_str(), bin.bits, bin.entry);

    for (size_t i = 0; i < bin.sections.size(); ++i) {
        sec = &bin.sections[i];
        printf("  0x%016jx %-8ju %-20s %s\n", sec->vma, sec->size, sec->name.c_str(),
                sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    if (bin.symbols.size() > 0) {
        puts("scanned symbol tables");
        for (size_t i = 0; i < bin.symbols.size(); ++i) {
            sym = &bin.symbols[i];
            printf("  %-40s 0x%016jx %s\n", sym->name.c_str(), sym->addr,
                    (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
        }
    }
#endif

    if ((text = bin.get_text_section()) == NULL) {
        puts("Nothing to disassemble");
        return 0;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        e = cs_errno(handle);
        puts(cs_strerror(e));
        exit(e);
    }

    if (!(cnt = cs_disasm(handle, text->bytes, text->size, text->vma, 0, &instructions))) {
        e = cs_errno(handle);
        puts(cs_strerror(e));
        exit(e);
    }

    for (size_t i = 0; i < cnt; ++i) {
        printf("0x%lx:\t%s\t\t%s\n", instructions[i].address, instructions[i].mnemonic,
					instructions[i].op_str);
    }

    cs_free(instructions, cnt);

    cs_close(&handle);

    unload_binary(&bin);

    return 0;
}