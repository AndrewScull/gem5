import analysis
from parser import Parser
from summary import Summary
from symboltable import SymbolTable

class ExecTrace:
    def __init__(self, instructions=[]):
        self.__instructions = instructions

    def load(self, fname, symtab):
        p = Parser()
        t = analysis.TraceBuilder()
        p.add_analysis(t)
        p.load(fname, symtab)
        self.__instructions = t.results()

    def __len__(self):
        return len(self.__instructions)

    def __iter__(self):
        return iter(self.__instructions)

    # unique instruction pointers and count per symbol
    def count_ips(self, fn):
        ips = {}
        for i in self.__instructions:
            if i.symbol() == fn:
                offset = i.address()
                ips[offset] = ips.get(offset, 0) + 1
        return ips

    def summary(self):
        # Pump the instruction through the analysers to generate the data
        # needed for the summary
        ip_analysis = analysis.SymbolIps()
        addr_analysis = analysis.AccessedAddresses()
        for i in self:
            ip_analysis.instruction(i)
            addr_analysis.instruction(i)
            for m in i:
                ip_analysis.microop(i, m)
                addr_analysis.microop(i, m)
        return str(Summary(ip_analysis, addr_analysis))

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

# Iterate the trace to generte a summary without having to create an in memory
# representation of the whole trace
def summarize(filename, symtab):
    p = Parser()
    ip_analysis = analysis.SymbolIps()
    addr_analysis = analysis.AccessedAddresses()
    p.add_analysis(ip_analysis)
    p.add_analysis(addr_analysis)
    p.load(filename, symtab)
    return str(Summary(ip_analysis, addr_analysis))

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

    if args.summary or not args.hotlines:
        print summarize(args.logfile, syms)
    if args.hotlines:
        trace.gethotlines(args.hotlines)

if __name__ == "__main__":
    main()
