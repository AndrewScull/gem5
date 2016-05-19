/*
 * Copyright (c) 2015-2016 Bjoern A. Zeeb
 * All rights reserved.
 *
 */

#include "arch/x86/freebsd/system.hh"

#include <cstring>

#include "arch/vtophys.hh"
#include "arch/x86/isa_traits.hh"
#include "arch/x86/regs/int.hh"
#include "arch/x86/system.hh"
#include "base/intmath.hh"
#include "base/trace.hh"
#include "cpu/thread_context.hh"
#include "debug/Loader.hh"
#include "mem/port_proxy.hh"
#include "params/FreeBSDX86System.hh"
#include "sim/byteswap.hh"

using namespace LittleEndianGuest;
using namespace X86ISA;

FreeBSDX86System::FreeBSDX86System(Params *p)
    : X86System(p), commandLine(p->boot_osflags),
    loaderConfig(p->loader_config), e820Table(p->e820_table)
{
}

FreeBSDX86System::~FreeBSDX86System()
{
}

void
FreeBSDX86System::initState()
{
    FreeBSDX86SystemHelper h = FreeBSDX86SystemHelper();
    X86System::setHelper(&h);
    X86System::initState();

    // The location of the real mode data structure.
    const Addr realModeData = 0x90200;

    /*
     * E820 memory map
     */

    // A pointer to the number of E820 entries there are.
    const Addr e820MapNrPointer = realModeData + 0x1e8;

    // A pointer to the buffer for E820 entries.
    const Addr e820MapPointer = realModeData + 0x2d0;

    e820Table->writeTo(physProxy, e820MapNrPointer, e820MapPointer);


    /*
     * Loader type.
     *
     * We have to repliacte a lot of work the FreeBSD loader normally
     * does for us.  We do a lot of C-style programming down there.
     */

    System *sys = threadContexts[0]->getSystemPtr();
    size_t kernsize = sys->getKernelEnd() - sys->getKernelStart();
    Addr addr = roundUp(sys->getKernelEnd(), PAGE_SIZE);
    Addr modulep = addr;
    DPRINTF(Loader, "modulep = %#x\n", modulep);

    // ------------------------------------------------------------------------
    // Write preloaded_file 'elf kernel' metainformation
    MOD_NAME(addr, std::string("/boot/kernel/kernel"), 1);
    MOD_TYPE(addr, std::string("elf kernel"), 1);
    //MOD_ARGS(addr, ..., 1);
    uint64_t v;
    v = sys->getKernelStart();
    MOD_ADDR(addr, v, 1);
    v = kernsize;
    MOD_SIZE(addr, v, 1);

    // ------------------------------------------------------------------------
    // Add various metadata information.

    const char *kargs;
    const char *cp;
    int         howto;
    int         active;

    /* Parse kargs */
    DPRINTF(Loader, "boot_osflags=%s\n", params()->boot_osflags);
    kargs = params()->boot_osflags.c_str();
    howto = 0;
    if (kargs != NULL) {
        cp = kargs;
        active = 0;
        while (*cp != 0) {
            if (!active && (*cp == '-')) {
                active = 1;
            } else if (active)
                switch (*cp) {
                case 'a':
                    howto |= RB_ASKNAME;
                    break;
                case 'C':
                    howto |= RB_CDROM;
                    break;
                case 'd':
                    howto |= RB_KDB;
                    break;
                case 'D':
                    howto |= RB_MULTIPLE;
                    break;
                case 'm':
                    howto |= RB_MUTE;
                    break;
                case 'g':
                    howto |= RB_GDB;
                    break;
                case 'h':
                    howto |= RB_SERIAL;
                    break;
                case 'p':
                    howto |= RB_PAUSE;
                    break;
                case 'r':
                    howto |= RB_DFLTROOT;
                    break;
                case 's':
                    howto |= RB_SINGLE;
                    break;
                case 'v':
                    howto |= RB_VERBOSE;
                    break;
                default:
                    active = 0;
                    break;
                }
            cp++;
        }
    }
    DPRINTF(Loader, "BootHowTo=%#x\n", howto);
    MOD_METADATA(addr, MODINFOMD_HOWTO, sizeof(howto), &howto, 1);

    // Don't write it out but consume the space and remember the addr
    // for the meta information.
    Addr envp = 0;
    Addr envp_meta_addr = 0;
    if (loaderConfig.size() > 0) {
        envp_meta_addr = addr;
        MOD_METADATA(addr, MODINFOMD_ENVP, sizeof(envp), &envp, 0);
        DPRINTF(Loader, "MODINFOMD_ENVP made space at = %#x addr now %#x\n",
            envp_meta_addr, addr);
    }

#if 0
    file_addmetadata(kfp, MODINFOMD_KERNEND, sizeof kernend, &kernend);
    file_addmetadata(kfp, MODINFOMD_MODULEP, sizeof module, &module);
#endif

    /* Add BIOS SMAP (E820) information. */
struct bios_smap {
    u_int64_t   base;
    u_int64_t   length;
    u_int32_t   type;
} __packed;
#if 0
/* Structure extended to include extended attribute field in ACPI 3.0. */
struct bios_smap_xattr {
    u_int64_t   base;
    u_int64_t   length;
    u_int32_t   type;
    u_int32_t   xattr;
} __packed;
#endif
    uint32_t SMAPsize = e820Table->entries.size() * sizeof(struct bios_smap);
    struct bios_smap *SMAPdata = (struct bios_smap *)malloc(SMAPsize);
    if (SMAPdata != NULL) {
        struct bios_smap *p = SMAPdata;
        for (int i=0; i < e820Table->entries.size(); i++) {
                p->base = e820Table->entries[i]->addr;
                p->length = e820Table->entries[i]->size;
                p->type = e820Table->entries[i]->type;
                DPRINTF(Loader, "SMAP: %d %#x-%#x l=%#x\n",
                    p->type, p->base, p->base + p->length, p->length);
                p++;
        }
        MOD_METADATA(addr, MODINFOMD_SMAP, SMAPsize, SMAPdata, 1);
        free(SMAPdata);
    } else {
        /* XXX-BZ abort? */
    }

    // ------------------------------------------------------------------------
    // end.
    MOD_END(addr, 1);


    Addr size = 0;
#if 0
    // XXXX-BZ We do not support loading kernel modules yet.
    size = bi_copymodules64(0);
#endif

    /* Copy our environment. */
    if (envp_meta_addr != 0x0) {
        std::vector<std::string>::iterator i;
        Addr p;
        const uint8_t z = '\0';

        p = envp = roundUp(addr + size, PAGE_SIZE);
        i = loaderConfig.begin();
        while (i != loaderConfig.end()) {
            std::string s = *i;
            physProxy.writeBlob(p, (uint8_t *)s.c_str(), s.length());
            p += s.length();
            i++;
            physProxy.writeBlob(p++, &z, 1);
            DPRINTF(Loader, "MODINFOMD_ENVP envp %#x %s %d \\0\n",
                    p, s.c_str(), s.length());
        }
        physProxy.writeBlob(p++, &z, 1);
        addr = p;
        DPRINTF(Loader, "MODINFOMD_ENVP envp %#x add %#x\n", envp, addr);
    }

    /* Set kernend. */
    kernsize = addr - sys->getKernelStart();
    //Addr kernend = roundUp(sys->getKernelEntry() + kernsize , PAGE_SIZE);
    Addr kernend = roundUp(addr , PAGE_SIZE);
    DPRINTF(Loader, "kernend (post-modules) = %#x (size=%#x)\n",
        kernend, kernsize);

#if 0
    /* patch MODINFOMD_KERNEND */
    md = file_findmetadata(kfp, MODINFOMD_KERNEND);
    bcopy(&kernend, md->md_data, sizeof kernend);
#endif

    /* Patch MODINFOMD_ENVP. */
    // We actually only write it out now.
    if (envp_meta_addr != 0x0) {
        DPRINTF(Loader, "MODINFOMD_ENVP set at %#x to %#x\n",
            envp_meta_addr, envp);
        MOD_METADATA(envp_meta_addr, MODINFOMD_ENVP, sizeof(envp), &envp, 1);
    }

#if 0
    /* copy module list and metadata */
    (void)bi_copymodules64(*modulep);
#endif

    /*
     * Here's what the kernel expects to find and where.
     * And that's what we write out.
     */
#if 0
    /* src/sys/amd64/amd64/locore.S */
    /* Find the metadata pointers before we lose them */
    movq    %rsp, %rbp
    movl    4(%rbp),%edi            /* modulep (arg 1) */
    movl    8(%rbp),%esi            /* kernend (arg 2) */
#endif

    Addr rsp = threadContexts[0]->readIntReg(X86ISA::INTREG_RSP);
    uint32_t x = modulep;
    physProxy.writeBlob(rsp + 4, (uint8_t *)&x, sizeof(x));
    x = kernend;
    physProxy.writeBlob(rsp + 8, (uint8_t *)&x, sizeof(x));
}

FreeBSDX86System *
FreeBSDX86SystemParams::create()
{
    return new FreeBSDX86System(this);
}

void
FreeBSDX86SystemHelper::setupPMAP(ThreadContext *tc)
{

    PortProxy &physProxy = tc->getPhysProxy();

    /* Reconstructed from FreeBSD loader. */

    /* Each slot of the level 4 pages points to the same level 3 page */
    u_int64_t p4 = (u_int64_t)(uintptr_t)PageDirPtrTable;
    p4 |= PG_V | PG_RW | PG_U;
    p4 = X86ISA::htog(p4);

    /* Each slot of the level 3 pages points to the same level 2 page */
    u_int64_t p3 = (u_int64_t)(uintptr_t)PageDirTable[0];
    p3 |= PG_V | PG_RW | PG_U;
    p3 = X86ISA::htog(p3);

    u_int64_t p2;
    int i;
    for (i = 0; i < 512; i++) {
        physProxy.writeBlob(PageMapLevel4 + i * 8, (uint8_t *)(&p4), 8);
        physProxy.writeBlob(PageDirPtrTable + i * 8, (uint8_t *)(&p3), 8);

        /* The level 2 page slots are mapped with 2MB pages for 1GB. */
        p2 = i * (2 * 1024 * 1024);
        p2 |= PG_V | PG_RW | PG_PS | PG_U;
        p2 = X86ISA::htog(p2);
        physProxy.writeBlob(PageDirTable[0] + i * 8, (uint8_t *)(&p2), 8);
#if 0
        physProxy.writeBlob(PageDirTable[1] + i * 8, (uint8_t *)(&p2), 8);
        physProxy.writeBlob(PageDirTable[2] + i * 8, (uint8_t *)(&p2), 8);
        physProxy.writeBlob(PageDirTable[3] + i * 8, (uint8_t *)(&p2), 8);
#endif
    }
    DPRINTF(Loader, "setupPMAP done\n");
}

void
FreeBSDX86SystemHelper::transitionToLongMode(ThreadContext *tc)
{
    /* Reconstructed from FreeBSD loader. */

    /*
     * Transition from real mode all the way up to Long mode
     */
    CR0 cr0;
    //Turn on protected mode.
    cr0 = tc->readMiscRegNoEffect(MISCREG_CR0);
    cr0.pe = 1;
    tc->setMiscReg(MISCREG_CR0, cr0);

    Efer efer = tc->readMiscRegNoEffect(MISCREG_EFER);
    //Enable long mode.
    efer.lme = 1;
    tc->setMiscReg(MISCREG_EFER, efer);

    CR4 cr4 = tc->readMiscRegNoEffect(MISCREG_CR4);
    //Turn on pae.
    cr4.pae = 1;
    tc->setMiscReg(MISCREG_CR4, cr4);

    //Point to the page tables.
    tc->setMiscReg(MISCREG_CR3, PageMapLevel4);

    // Turn on paging.
    cr0 = tc->readMiscRegNoEffect(MISCREG_CR0);
    cr0.pg = 1;
    tc->setMiscReg(MISCREG_CR0, cr0);

    /* Now we're in compatability mode. set %cs for long mode */
    DPRINTF(Loader,
            "Now we're in compatability mode. set %%cs for long mode\n");
}
