class Summary:
    def __init__(self, ip_analysis, addr_analysis):
        sym_ips = ip_analysis.symbol_ips()
        total_ips = sum(sym_ips.values())
        sym_uniq_ips = ip_analysis.symbol_unique_ips()

        mem = addr_analysis.num_memory_accesses()
        addr = addr_analysis.num_addresses()
        total_mem = sum(mem.itervalues())
        total_addr = sum(addr.itervalues())

        mem_read = addr_analysis.num_read_accesses()
        mem_write = addr_analysis.num_write_accesses()
        addr_read = addr_analysis.num_read_addresses()
        addr_write = addr_analysis.num_write_addresses()


        # Totals
        self.__totals = {
            'instr': total_ips,
            'uniq': sum(sym_uniq_ips.itervalues()),
            'mem': total_mem,
            'addr': total_addr,
        }

        # Intructions
        instr_summary = {}
        for sym,ips in sym_ips.iteritems():
            instr_summary[sym] = {
                'instr': ips,
                '%': ips*100.0/total_ips,
                'uniq': sym_uniq_ips[sym],
            }
        self.__instr = instr_summary

        # Memory accesses
        mem_summary = {}
        for sym,mems in mem.iteritems():
            reads = mem_read.get(sym, 0)
            writes = mem_write.get(sym, 0)
            mem_summary[sym] = {
                'mem': mems,
                '%': mems*100.0/total_mem,
                'read': reads,
                'r%': reads*100.0/mems if mems else 0,
                'write': writes,
                'w%': writes*100.0/mems if mems else 0,
            }
        self.__mem = mem_summary

        # Address accesses
        addr_summary = {}
        for sym,addrs in addr.iteritems():
            reads = addr_read.get(sym, 0)
            writes = addr_write.get(sym, 0)
            addr_summary[sym] = {
                'addr': addrs,
                '%': addrs*100.0/total_addr,
                'read': reads,
                'r%': reads*100.0/addrs if addrs else 0,
                'write': writes,
                'w%': writes*100.0/addrs if addrs else 0,
            }
        self.__addr = addr_summary

    def __str__(self):
        ret = ''

        # Totals
        fields = [
            ('instr', 'total instructions'),
            ('uniq', 'total unique ips'),
            ('mem', 'total memory accesses'),
            ('addr', 'total addresses accessed'),
        ]
        ret += '\n'
        for f in fields:
            ret += str(self.__totals[f[0]]) + ' ' + f[1] + '\n'

        # Instruction results
        ret += self.__table(self.__instr, 'instr', [
            ('instr', 'Instrs'),
            ('%', '%'),
            ('uniq', 'Uniq'),
        ])

        # Memory accesses
        ret += self.__table(self.__mem, 'mem', [
            ('mem', 'Mem'),
            ('%', '%'),
            ('read', 'Read'),
            ('r%', '%'),
            ('write', 'Write'),
            ('w%', '%'),
        ])

        # Address accesses
        ret += self.__table(self.__addr, 'addr', [
            ('addr', 'Addr'),
            ('%', '%'),
            ('read', 'Read'),
            ('r%', '%'),
            ('write', 'Write'),
            ('w%', '%'),
        ])

        return ret

    def __table(self, data, key, fields):
        ret = '\n'
        ret += '\t'.join([f[1] for f in fields] + ['Symbol'])
        ret += '\n' + '--------'*(len(fields)+1) + '\n'
        for sym,res in sorted(data.iteritems(),
                key=lambda (x, y): y[key], reverse=True):
            for f in fields:
                val = res[f[0]]
                if isinstance(val, float):
                    ret += '%.2f\t' % val
                else:
                    ret += str(val) + '\t'
            ret += str(sym) + '\n'
        return ret

    def totals(self):
        return self.__totals

    def instr(self):
        return self.__instr

    def mem(self):
        return self.__mem

    def addr(self):
        return self._addr
