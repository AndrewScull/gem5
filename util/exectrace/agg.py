import analysis
from aggregate import Aggregate
from parser import Parser
from summary import Summary
from symboltable import SymbolTable

from exectrace import summarize

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(
            description='Parse instruction traces.')
    parser.add_argument('path', metavar='FILE',
            help='Base of names before the .1 etc..')
    parser.add_argument('num', type=int)
    parser.add_argument('--jit', action='store_true',
            help='Is it the jit version?')
    return parser.parse_args()

def aggregate(path, num, syms):
    sums = [summarize(path+'.'+str(i+1), syms) for i in range(num)]
    agg = Aggregate(sums)
    return agg

def main():
    args = parse_args()

    if args.jit:
        symfile = '/gem5/experiments/exports/dtrace_jit.ko.symbols'
        symbase = 0xffffffff80a16000
    else:
        symfile = '/gem5/freebsd/inst/boot/kernel/dtrace.ko.symbols'
        symbase = 0xffffffff80a16000

    syms = SymbolTable(symfile, symbase)

    print str(aggregate(args.path, args.num, syms))


if __name__ == "__main__":
    main()
