from instruction import Instruction
from microop import MicroOp

class Parser:
    def __init__(self):
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
        self.__analyses = []

    def add_analysis(self, a):
        self.__analyses.append(a)

    def analyses(self):
        return self.__analyses

    def load(self, filename, symtab):
        with open(filename) as trace:
            self.__lineno = 0
            instruction = None
            for line in trace:
                self.__lineno += 1
                op = self.__parse_line(line, symtab)
                if isinstance(op, Instruction):
                    instruction = op
                    self.__emit_instruction(instruction);
                else:
                    self.__emit_microop(instruction, op)

    def __emit_instruction(self, instruction):
        for a in self.__analyses:
            a.instruction(instruction)

    def __emit_microop(self, instruction, microop):
        for a in self.__analyses:
            a.microop(instruction, microop)

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
