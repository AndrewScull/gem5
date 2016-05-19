/*
 * Copyright (c) 2015-2016 Bjoern A. Zeeb
 * All rights reserved.
 *
 */

#ifndef __ARCH_FREEBSD_X86_SYSTEM_HH__
#define __ARCH_FREEBSD_X86_SYSTEM_HH__

#include <string>
#include <vector>

#include "arch/x86/bios/e820.hh"
#include "arch/x86/system.hh"
#include "params/FreeBSDX86System.hh"

/*
 * The following definitions have been replicated from FreeBSD's
 * sys/boot/.. directory.
 * We wish that the FreeBSD framework had a proper single source
 * for these things rather than a lot of copy&paste, so we could just
 * include a clean file.
 */

/* Page size definition for amd64, so we can properly align things. */
#define PAGE_SHIFT  12              /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE   (1<<PAGE_SHIFT) /* bytes/page */

/*
 * Modinfo definitions in order to pass meta-information in to the
 * kernel environment.
 */
/* From src/sys/linker.h */
#define MODINFO_END             0x0000          /* End of list */
#define MODINFO_NAME            0x0001          /* Name of module (string) */
#define MODINFO_TYPE            0x0002          /* Type of module (string) */
#define MODINFO_ADDR            0x0003          /* Loaded address */
#define MODINFO_SIZE            0x0004          /* Size of module */
#define MODINFO_EMPTY           0x0005          /* Has been deleted */
#define MODINFO_ARGS            0x0006          /* Parameters string */
#define MODINFO_METADATA        0x8000          /* Module-specfic */

#define MODINFOMD_ENVP          0x0006          /* envp[] */
#define MODINFOMD_HOWTO         0x0007          /* boothowto */
#define MODINFOMD_KERNEND       0x0008          /* kernend */

/* From src/sys/amd64/include/metadata.h */
#define MODINFOMD_SMAP          0x1001
#define MODINFOMD_SMAP_XATTR    0x1002
#define MODINFOMD_MODULEP       0x1006

/*
 * Adjusted macros to write out the individual modinfo meta-information.
 */
/* Based on src/sys/boot/i386/libi386/bootinfo64.c */
/*
 * Copy module-related data into the load area, where it can be
 * used as a directory for loaded modules.
 *
 * Module data is presented in a self-describing format.  Each datum
 * is preceded by a 32-bit identifier and a 32-bit size field.
 *
 * Currently, the following data are saved:
 *
 * MOD_NAME     (variable)              module name (string)
 * MOD_TYPE     (variable)              module type (string)
 * MOD_ARGS     (variable)              module parameters (string)
 * MOD_ADDR     sizeof(vm_offset_t)     module load address
 * MOD_SIZE     sizeof(size_t)          module size
 * MOD_METADATA (variable)              type-specific metadata
 */
#define COPY32(v, a, c) {                       \
    u_int32_t   x = (v);                        \
    if (c)                                      \
        physProxy.writeBlob(a, (uint8_t *)&x, sizeof(x)); \
    a += sizeof(x);                             \
}

#define MOD_STR(t, a, s, c) {                   \
    COPY32(t, a, c);                            \
    COPY32(s.size() + 1, a, c);                 \
    if (c) {                                    \
        physProxy.writeBlob(a, (uint8_t *)s.c_str(), s.size() + 1); \
    }                                           \
    a += roundUp(s.size() + 1, sizeof(u_int64_t)); \
}

#define MOD_NAME(a, s, c)       MOD_STR(MODINFO_NAME, a, s, c)
#define MOD_TYPE(a, s, c)       MOD_STR(MODINFO_TYPE, a, s, c)
#define MOD_ARGS(a, s, c)       MOD_STR(MODINFO_ARGS, a, s, c)

#define MOD_VAR(t, a, s, c) {                   \
    COPY32(t, a, c);                            \
    COPY32(sizeof(s), a, c);                    \
    if (c)                                      \
        physProxy.writeBlob(a, (uint8_t *)&s, sizeof(s)); \
    a += roundUp(sizeof(s), sizeof(u_int64_t)); \
}

#define MOD_ADDR(a, s, c)       MOD_VAR(MODINFO_ADDR, a, s, c)
#define MOD_SIZE(a, s, c)       MOD_VAR(MODINFO_SIZE, a, s, c)

#define MOD_METADATA(a, type, size, data, c) {  \
    COPY32(MODINFO_METADATA | type, a, c);      \
    COPY32(size, a, c);                         \
    if (c)                                      \
        physProxy.writeBlob(a, (uint8_t *)data, size); \
    a += roundUp(size, sizeof(u_int64_t));      \
}

#define MOD_END(a, c) {                         \
    COPY32(MODINFO_END, a, c);                  \
    COPY32(0, a, c);                            \
}

/*
 * BootHowTo definitions.
 */
/* Based on src/sys/boot/i386/libi386/bootinfo.c, src/sys/sys/reboot.c. */
#define RB_AUTOBOOT  0       /* flags for system auto-booting itself */
#define RB_ASKNAME   0x001   /* ask for file name to reboot from */
#define RB_SINGLE    0x002   /* reboot to single user only */
#define RB_NOSYNC    0x004   /* dont sync before reboot */
#define RB_HALT      0x008   /* don't reboot, just halt */
#define RB_INITNAME  0x010   /* name given for /etc/init (unused) */
#define RB_DFLTROOT  0x020   /* use compiled-in rootdev */
#define RB_KDB       0x040   /* give control to kernel debugger */
#define RB_RDONLY    0x080   /* mount root fs read-only */
#define RB_DUMP      0x100   /* dump kernel memory before reboot */
#define RB_MINIROOT  0x200   /* mini-root present in memory at boot time */
#define RB_VERBOSE   0x800   /* print all potentially useful info */
#define RB_SERIAL    0x1000  /* use serial port as console */
#define RB_CDROM     0x2000  /* use cdrom as root */
#define RB_POWEROFF  0x4000  /* turn the power off if possible */
#define RB_GDB       0x8000  /* use GDB remote debugger instead of DDB */
#define RB_MUTE      0x10000 /* start up with the console muted */
#define RB_SELFTEST  0x20000 /* don't complete the boot; do selftest */
#define RB_RESERVED1 0x40000 /* reserved for internal use of boot blocks */
#define RB_RESERVED2 0x80000 /* reserved for internal use of boot blocks */
#define RB_PAUSE     0x100000 /* pause after each output line during probe */
#define RB_MULTIPLE  0x20000000 /* use multiple consoles */
#define RB_BOOTINFO  0x80000000 /* have `struct bootinfo *' arg */

/* Page Table Flags. */
#define PG_V  0x001
#define PG_RW 0x002
#define PG_U  0x004
#define PG_PS 0x080

class FreeBSDX86SystemHelper : public X86SystemHelper
{

  public:
    virtual void setupPMAP(ThreadContext *);
    virtual void transitionToLongMode(ThreadContext *);
};

class FreeBSDX86System : public X86System
{
  protected:
    std::string commandLine;
    std::vector<std::string> loaderConfig;	// Just tunables a=b
    size_t loaderConfigLen;
    X86ISA::E820Table * e820Table;

  public:
    typedef FreeBSDX86SystemParams Params;
    FreeBSDX86System(Params *p);
    ~FreeBSDX86System();

    void initState();
};

#endif
