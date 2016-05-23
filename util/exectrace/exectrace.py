from instruction import Instruction
from microop import MicroOp
from symboltable import SymbolTable

class ExecTrace:
    def __init__(self, instructions=[]):
        self.__instructions = instructions

    def load(self, fname, symtab):
        # See: src/cpu/exetrace.cc
        # python regex is slow but this is the structure:
        #
        # '^(\d+): ' + # tick
        # '([^:]+) (A(\d+) )?(T(\d+) ): ' + # cpu (asid) (thread)
        # '(@([^\+\.\s]+)(\+(\d+))?|(0x[0-9A-Fa-f]+))(\.(\d+))?' + # symbol
        # ' +: +(.+?) *' + # asm
        # '( : +(.+?) *( :|$))?' + # micro op asm
        # '( (.+) : )?' + # op class
        # '(Predicated False)?' +
        # '( +D=(0x[0-9A-Fa-f]+))?' +
        # '( +A=(0x[0-9A-Fa-f]+))?' +
        # '( +FetchSeq=(\d+))?' +
        # '( +CPSeq=(\d+))?' +
        # '( +flags=(\([^\)]*\)))?$'
        import re
        self.__sym_re = re.compile(
                '(@([^\+\.\s]+)(\+(\d+))?|(0x[0-9A-Fa-f]+))(\.(\d+))?')
        self.__instructions = []
        self.__last_sym = None
        self.__lineno = 0
        with open(fname) as trace:
            for line in trace:
                self.__lineno += 1
                op = self.__parse_line(line, symtab)
                if isinstance(op, Instruction):
                    self.__instructions.append(op)
                elif self.__instructions:
                    self.__instructions[-1].add_micro_op(op)

    def __parse_line(self, line, symtab):
        fields = line.split(': ')

        sym_match = self.__sym_re.match(fields[2])
        if not sym_match:
            raise IOError('Unknown symbol format on line {}: {}'.format(
                    self.__lineno, fields[2]))
        (sym, offset, addr, micro_op_num) = sym_match.group(2,4,5,7)
        offset = int(offset) if offset else None
        addr = int(addr, 16) if addr else None
        micro_op_num = int(micro_op_num) if micro_op_num else None

        if addr and symtab:
            sym = symtab.getsym(addr)
            self.__last_sym = sym

        if micro_op_num == None:
            cpu = fields[1][:-1]
            return Instruction(
                    tick=int(fields[0]),
                    cpu=cpu,
                    symbol=sym,
                    offset=offset,
                    address=addr,
                    asm=fields[3].strip())
        else:
            if len(fields) != 7:
                raise IOError('Unknown micro op format on line {}: {}'.format(
                        self.__lineno, line))
            details = fields[6].split(' ')
            extras = {
                    'D': None,
                    'A': None,
                }
            for d in details:
                eq_idx = d.find('=')
                if eq_idx != -1:
                    key = d[:eq_idx]
                    if key in extras:
                        extras[key] = int(d[eq_idx+1:], 16)

            kind = fields[5][:-1]
            microop = fields[3].strip()

            return MicroOp(
                instruction=microop,
                    asm=fields[4][:-1],
                    kind=kind,
                    data=extras['D'],
                    address=extras['A'])

    def __len__(self):
        return len(self.__instructions)

    def __iter__(self):
        return iter(self.__instructions)

    # unique instruction pointers and count
    def unique_ips(self):
        ips = {}
        for i in self.__instructions:
            if i.address():
                ip = i.address()
            elif i.offset():
                ip = '{}+{}'.format(i.symbol(), i.offset())
            else:
                ip = i.symbol()
            ips[ip] = ips.get(ip, 0) + 1
        return len(ips)

    # instruction count per symbol (instructions per named functions)
    def symbol_ips(self):
        ips = {}
        for i in self.__instructions:
            if i.symbol():
                ips[i.symbol()] = ips.get(i.symbol(), 0) + 1
        return ips

    # unique instruction pointers and count per symbol
    def symbol_unique_ips(self):
        syms = {}
        for i in self.__instructions:
            if i.symbol():
                ips = syms.setdefault(i.symbol(), {})
                offset = i.address()
                ips[offset] = ips.get(offset, 0) + 1
        return {k: len(v) for k,v in syms.iteritems()}

    # unique instruction pointers and count per symbol
    def count_ips(self, fn):
        ips = {}
        for i in self.__instructions:
            if i.symbol() == fn:
                offset = i.address()
                ips[offset] = ips.get(offset, 0) + 1
        return ips

    # count of accesses to memory addresses
    def addresses(self, per_symbol=False, kind=None):
        if per_symbol:
            syms = {}
        addrs = {}
        for i in self.__instructions:
            if per_symbol:
                if not i.symbol():
                    continue
                addrs = syms.setdefault(i.symbol(), {})
            for m in i:
                if m.address():
                    if not kind or m.kind() == kind:
                        addrs[m.address()] = addrs.setdefault(
                                m.address(), 0) + 1
        return syms if per_symbol else addrs

    def summary(self):
        sym_ips = self.symbol_ips()
        total_ips = sum(sym_ips.values())
        sym_uniq_ips = self.symbol_unique_ips()
        sym_addr = self.addresses(per_symbol=True)
        mem  = {k: sum(v.values()) for k,v in sym_addr.iteritems()}
        addr = {k: len(v.values()) for k,v in sym_addr.iteritems()}
        read  = self.addresses(per_symbol=True, kind='MemRead')
        write = self.addresses(per_symbol=True, kind='MemWrite')
        mem_read   = {k: sum(v.values()) for k,v in read.iteritems()}
        mem_write  = {k: sum(v.values()) for k,v in write.iteritems()}
        addr_read  = {k: len(v.values()) for k,v in read.iteritems()}
        addr_write = {k: len(v.values()) for k,v in write.iteritems()}

        ret = ''

        # Totals
        ret += '\n'
        ret += str(sum(sym_ips.values())) + ' total instructions\n'
        ret += str(sum(sym_uniq_ips.values())) + ' total unique ips\n'
        ret += str(sum(mem.values())) + ' total memory accesses\n'
        ret += str(sum(addr.values())) + ' total addresses accessed\n'

        # Instruction results
        ret += '\n'
        ret += '\t'.join(['Instrs', 'I_per', 'Uniq', 'Symbol'])
        ret += '\n' +'--------'*4 + '\n'
        for sym in sorted(sym_ips, key=sym_ips.get, reverse=True):
            ips = sym_ips[sym]
            ret += str(ips) + '\t'
            ret += '%.2f\t' % (ips*100.0/total_ips)
            ret += str(sym_uniq_ips[sym]) + '\t'
            ret += sym
            ret += '\n'

        # Memory accesses
        ret += '\n'
        ret += '\t'.join(['Mem', 'Read', 'R_per', 'Write', 'W_per', 'Symbol'])
        ret += '\n' + '--------'*6 + '\n'
        for sym in sorted(sym_ips, key=sym_ips.get, reverse=True):
            mems = mem.get(sym, 0)
            ret += str(mems) + '\t'
            reads = mem_read.get(sym, 0)
            ret += str(reads) + '\t'
            ret += '%.2f\t' % ((reads*100.0/mems) if mems else 0)
            writes = mem_write.get(sym, 0)
            ret += str(writes) + '\t'
            ret += '%.2f\t' % ((writes*100.0/mems) if mems else 0)
            ret += sym
            ret += '\n'

        # Address accesses
        ret += '\n'
        ret += '\t'.join(['Addr', 'Read', 'R_per', 'Write', 'W_per', 'Symbol'])
        ret += '\n' + '--------'*6 + '\n'
        for sym in sorted(sym_ips, key=sym_ips.get, reverse=True):
            addrs = addr.get(sym, 0)
            ret += str(addrs) + '\t'
            reads = addr_read.get(sym, 0)
            ret += str(reads) + '\t'
            ret += '%.2f\t' % ((reads*100.0/addrs) if addrs else 0)
            writes = addr_write.get(sym, 0)
            ret += str(writes) + '\t'
            ret += '%.2f\t' % ((writes*100.0/addrs) if addrs else 0)
            ret += sym
            ret += '\n'

        return ret

    def gethotlines(self, fn, base=0xffffffff80a16000):
        import os
        ip_cnt = sorted_by_values(self.count_ips(fn), reverse=True)
        ips = [a-base for a,b in ip_cnt]
        cmd = 'addr2line -e /gem5/freebsd/inst/boot/kernel/dtrace.ko.symbols'
        for i in ips:
            cmd += ' ' + hex(i)
        lines = {}
        for line,(addr,nr) in zip(os.popen(cmd).read().split('\n'),ip_cnt):
            (c,a) = lines.get(line, (0,[]))
            lines[line] = (c+nr, a + [addr])
        for line,(nr,addr) in sorted_by_values(lines, reverse=True):
            print nr, line[line.rfind('/'):], '[', ' '.join(
                    '%02x' % (a-base) for a in sorted(addr)), ']'


def sorted_by_values(obj, cmp=None, reverse=False):
    return sorted(obj.items(), cmp, lambda x: x[1], reverse)

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(
            description='Parse instruction traces.')
    parser.add_argument('logfile', metavar='FILE',
            help='Instruction trace log file to parse.')
    parser.add_argument('--summary', action='store_true',
            help='Print a summary of analysis')
    parser.add_argument('--hotlines', type=str,
            help='Print hot line for a function')
    return parser.parse_args()

def debug_load(log='/gem5/experiments/m5out/sim00001/debug.log'):
    syms = SymbolTable('/gem5/freebsd/inst/boot/kernel/dtrace.ko.symbols',
            0xffffffff80a16000)
    trace = ExecTrace()
    trace.load(log, syms)
    return trace

def main():
    args = parse_args()

    syms = SymbolTable('/gem5/freebsd/inst/boot/kernel/dtrace.ko.symbols',
            0xffffffff80a16000)

    trace = ExecTrace()
    trace.load(args.logfile, syms)

    if args.summary or not args.hotlines:
        print trace.summary()
    if args.hotlines:
        trace.gethotlines(args.hotlines)

if __name__ == "__main__":
    main()
