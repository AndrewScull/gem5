/*
 * Copyright (c) 2007-2008 The Hewlett-Packard Development Company
 * All rights reserved.
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Gabe Black
 */

#include "arch/x86/linux/system.hh"
#include "arch/x86/regs/int.hh"
#include "arch/x86/isa_traits.hh"
#include "arch/vtophys.hh"
#include "arch/x86/system.hh"
#include "base/trace.hh"
#include "cpu/thread_context.hh"
#include "mem/port_proxy.hh"
#include "params/LinuxX86System.hh"
#include "sim/byteswap.hh"

using namespace LittleEndianGuest;
using namespace X86ISA;

LinuxX86System::LinuxX86System(Params *p)
    : X86System(p), commandLine(p->boot_osflags), e820Table(p->e820_table)
{
}

LinuxX86System::~LinuxX86System()
{
}

void
LinuxX86System::initState()
{
    LinuxX86SystemHelper h = LinuxX86SystemHelper();
    X86System::setHelper(&h);
    X86System::initState();

    // The location of the real mode data structure.
    const Addr realModeData = 0x90200;

    /*
     * Deal with the command line stuff.
     */

    // A buffer to store the command line.
    const Addr commandLineBuff = 0x90000;
    // A pointer to the commandLineBuff stored in the real mode data.
    const Addr commandLinePointer = realModeData + 0x228;

    if (commandLine.length() + 1 > realModeData - commandLineBuff)
        panic("Command line \"%s\" is longer than %d characters.\n",
                commandLine, realModeData - commandLineBuff - 1);
    physProxy.writeBlob(commandLineBuff, (uint8_t *)commandLine.c_str(),
                        commandLine.length() + 1);

    // Generate a pointer of the right size and endianness to put into
    // commandLinePointer.
    uint32_t guestCommandLineBuff =
        X86ISA::htog((uint32_t)commandLineBuff);
    physProxy.writeBlob(commandLinePointer, (uint8_t *)&guestCommandLineBuff,
                        sizeof(guestCommandLineBuff));

    /*
     * Screen Info.
     */

    // We'll skip on this for now because it's only needed for framebuffers,
    // something we don't support at the moment.

    /*
     * EDID info
     */

    // Skipping for now.

    /*
     * Saved video mode
     */

    // Skipping for now.

    /*
     * Loader type.
     */

    // Skipping for now.

    /*
     * E820 memory map
     */

    // A pointer to the number of E820 entries there are.
    const Addr e820MapNrPointer = realModeData + 0x1e8;

    // A pointer to the buffer for E820 entries.
    const Addr e820MapPointer = realModeData + 0x2d0;

    e820Table->writeTo(physProxy, e820MapNrPointer, e820MapPointer);

    /*
     * Pass the location of the real mode data structure to the kernel
     * using register %esi. We'll use %rsi which should be equivalent.
     */
    threadContexts[0]->setIntReg(INTREG_RSI, realModeData);
}

LinuxX86System *
LinuxX86SystemParams::create()
{
    return new LinuxX86System(this);
}

void
LinuxX86SystemHelper::setupPMAP(ThreadContext *tc)
{
    const int PML4Bits = 9;
    const int PDPTBits = 9;
    const int PDTBits = 9;

    PortProxy &physProxy = tc->getPhysProxy();

    // Page Map Level 4

    // read/write, user, not present
    uint64_t pml4e = X86ISA::htog(0x6);
    for (int offset = 0; offset < (1 << PML4Bits) * 8; offset += 8) {
        physProxy.writeBlob(PageMapLevel4 + offset, (uint8_t *)(&pml4e), 8);
    }
    // Point to the only PDPT
    pml4e = X86ISA::htog(0x7 | PageDirPtrTable);
    physProxy.writeBlob(PageMapLevel4, (uint8_t *)(&pml4e), 8);

    // Page Directory Pointer Table

    // read/write, user, not present
    uint64_t pdpe = X86ISA::htog(0x6);
    for (int offset = 0; offset < (1 << PDPTBits) * 8; offset += 8) {
        physProxy.writeBlob(PageDirPtrTable + offset,
                            (uint8_t *)(&pdpe), 8);
    }
    // Point to the PDTs
    for (int table = 0; table < NumPDTs; table++) {
        pdpe = X86ISA::htog(0x7 | PageDirTable[table]);
        physProxy.writeBlob(PageDirPtrTable + table * 8,
                            (uint8_t *)(&pdpe), 8);
    }

    // Page Directory Tables

    Addr base = 0;
    const Addr pageSize = 2 << 20;
    for (int table = 0; table < NumPDTs; table++) {
        for (int offset = 0; offset < (1 << PDTBits) * 8; offset += 8) {
            // read/write, user, present, 4MB
            uint64_t pdte = X86ISA::htog(0x87 | base);
            physProxy.writeBlob(PageDirTable[table] + offset,
                                (uint8_t *)(&pdte), 8);
            base += pageSize;
        }
    }
}

void
LinuxX86SystemHelper::transitionToLongMode(ThreadContext *tc)
{

    /*
     * Transition from real mode all the way up to Long mode
     */
    CR0 cr0 = tc->readMiscRegNoEffect(MISCREG_CR0);
    //Turn off paging.
    cr0.pg = 0;
    tc->setMiscReg(MISCREG_CR0, cr0);
    //Turn on protected mode.
    cr0.pe = 1;
    tc->setMiscReg(MISCREG_CR0, cr0);

    CR4 cr4 = tc->readMiscRegNoEffect(MISCREG_CR4);
    //Turn on pae.
    cr4.pae = 1;
    tc->setMiscReg(MISCREG_CR4, cr4);

    //Point to the page tables.
    tc->setMiscReg(MISCREG_CR3, PageMapLevel4);

    Efer efer = tc->readMiscRegNoEffect(MISCREG_EFER);
    //Enable long mode.
    efer.lme = 1;
    tc->setMiscReg(MISCREG_EFER, efer);

    //Activate long mode.
    cr0.pg = 1;
    tc->setMiscReg(MISCREG_CR0, cr0);
}
