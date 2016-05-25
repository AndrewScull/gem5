class Instruction:
    def __init__(self, tick, cpu, symbol, line, offset, address, asm):
        self.__tick = tick
        self.__cpu = cpu
        self.__symbol = symbol
        self.__source_line = line
        self.__offset = offset
        self.__address = address
        self.__asm = asm
        self.__micro_ops = []

    def add_micro_op(self, op):
        self.__micro_ops.append(op)

    def __len__(self):
        return len(self.__micro_ops)

    def __iter__(self):
        return iter(self.__micro_ops)

    def tick(self):
        return self.__tick
    def cpu(self):
        return self.__cpu
    def symbol(self):
        return self.__symbol
    def source_line(self):
        return self.__source_line
    def offset(self):
        return self.__offset
    def address(self):
        return self.__address
    def asm(self):
        return self.__asm

