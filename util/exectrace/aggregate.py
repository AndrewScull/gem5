class Aggregate:
    def __init__(self, sums):
        # Totals
        self.__totals = {}
        for f in ['instr', 'uniq', 'mem', 'addr']:
            self.__totals[f] = self.__quarts([s.totals()[f] for s in sums])

        # Intructions
        self.__instr = {}
        for sym in sums[0].instr().iterkeys():
            self.__instr[sym] = {
                    f: self.__quarts([s.instr()[sym][f] for s in sums])
                        for f in ['instr', '%', 'uniq']}

        # Memory accesses
        self.__mem = {}
        for sym in sums[0].mem().iterkeys():
            self.__mem[sym] = {
                    f: self.__quarts([s.mem()[sym][f] for s in sums])
                        for f in ['mem', '%', 'read', 'r%', 'write', 'w%']}

        # Address accesses
        self.__addr = {}
        for sym in sums[0].addr().iterkeys():
            self.__addr[sym] = {
                    f: self.__quarts([s.addr()[sym][f] for s in sums])
                        for f in ['addr', '%', 'read', 'r%', 'write', 'w%']}

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
        for f,n in fields:
            ret += str(self.__totals[f]) + ' ' + str(n) + '\n'

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
        ret += '\t'.join([n for _,n in fields] + ['Symbol'])
        ret += '\n' + '--------'*(len(fields)+1) + '\n'
        for sym,res in sorted(data.iteritems(),
                key=lambda (x, y): y[key][1], reverse=True):
            for f,_ in fields:
                ret += '('
                for val in  res[f]:
                    if isinstance(val, float):
                        ret += '%.2f\t' % val
                    else:
                        ret += str(val) + '\t'
                ret += ')'
            ret += str(sym) + '\n'

        return ret

    def __median(self, sortedPoints):
        mid = len(sortedPoints) / 2
        if len(sortedPoints) % 2 == 0:
            return (sortedPoints[mid-1] + sortedPoints[mid]) / 2.0
        else:
            return sortedPoints[mid]

    def __quarts(self, data):
        d = sorted(data)
        med = self.__median(d)
        mid = len(d) / 2
        lowerQ = self.__median(d[:mid])
        if len(d) % 2 == 0:
            upperQ = self.__median(d[mid:])
        else:
            upperQ = self.__median(d[mid+1:])
        return (lowerQ, med, upperQ)

    def totals(self):
        return self.__totals

    def instr(self):
        return self.__instr

    def mem(self):
        return self.__mem

    def addr(self):
        return self.__addr
