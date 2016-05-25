class Analysis:
    def instruction(self, instr):
        pass
    def microop(self, instr, microop):
        pass
    def results(self):
        return None

# Build an in memory instruction trace
class TraceBuilder(Analysis):
    def __init__(self):
        self.__instructions = []

    def instruction(self, instr):
        self.__instructions.append(instr)

    def microop(self, instr, microop):
        instr.add_micro_op(microop)

    def results(self):
        return self.__instructions

# Count the number of instructions per source code line
class SourceLines(Analysis):
    def __init__(self, fn=None):
        self.__fn = fn
        self.__lines = {}

    def instruction(self, instr):
        if self.__fn and not instr.symbol() == self.__fn:
            return
        line = self.__lines.setdefault(instr.source_line(), {})
        addr = instr.address()
        line[addr] = line.get(addr, 0) + 1

    def results(self):
        return self.__lines

# Collect the instruction pointers used by each symbol
class SymbolIps(Analysis):
    def __init__(self):
        self.__syms = {}

    def instruction(self, instr):
        ips = self.__syms.setdefault(instr.symbol(), {})
        addr = instr.address()
        ips[addr] = ips.get(addr, 0) + 1

    def results(self):
        return self.__syms

    def symbol_ips(self):
        return {k: sum(v.values()) for k,v in self.__syms.iteritems()}

    def symbol_unique_ips(self):
        return {k: len(v) for k,v in self.__syms.iteritems()}

# Pick out memory accesses in the microops
class AccessedAddresses(Analysis):
    def __init__(self):
        self.__syms = {}

    def microop(self, instr, microop):
        if not microop.address():
            return
        kinds = self.__syms.setdefault(instr.symbol(), {})
        addrs = kinds.setdefault(microop.kind(), {})
        addr = microop.address()
        addrs[addr] = addrs.get(addr, 0) + 1

    def results(self):
        return self.__syms

    def num_memory_accesses(self):
        return {k: sum(sum(m.itervalues()) for m in v.itervalues())
                for k,v in self.__syms.iteritems()}

    def num_read_accesses(self):
        return {k: sum(v['MemRead'].itervalues())
                if 'MemRead' in v else 0
                for k,v in self.__syms.iteritems()}

    def num_write_accesses(self):
        return {k: sum(v['MemWrite'].itervalues())
                if 'MemWrite' in v else 0
                for k,v in self.__syms.iteritems()}

    def num_addresses(self):
        ret = {}
        for k,v in self.__syms.iteritems():
            addrs = set()
            for m in v.itervalues():
                addrs.update(m.iterkeys())
            ret[k] = len(addrs)
        return ret

    def num_read_addresses(self):
        return {k: len(v['MemRead'])
                if 'MemRead' in v else 0
                for k,v in self.__syms.iteritems()}

    def num_write_addresses(self):
        return {k: len(v['MemWrite'])
                if 'MemWrite' in v else 0
                for k,v in self.__syms.iteritems()}
