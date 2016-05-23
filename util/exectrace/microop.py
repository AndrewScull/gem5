class MicroOp:
    def __init__(self, instruction, asm, kind, data, address):
        self.__instruction = instruction
        self.__asm = asm
        self.__kind = kind
        self.__data = data
        self.__address = address

    def instruction(self):
        return self.__instruction
    def asm(self):
        return self.__asm
    def kind(self):
        return self.__kind
    def data(self):
        return self.__data
    def address(self):
        return self.__address
