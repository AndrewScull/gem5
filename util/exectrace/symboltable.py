class SymbolTable:
    def __init__(self, path, base):
        self.__syms = {}
        self.__path = path
        self.__base = base

    def getsym(self, addr):
        import os
        if not addr in self.__syms:
            if addr < self.__base:
                return None
            cmd = 'addr2line -fe ' + self.__path + ' ' + hex(addr-self.__base)
            self.__syms[addr] = os.popen(cmd).read().split('\n')[:-1]
        return self.__syms[addr]

    def base(self):
        return self.__base
