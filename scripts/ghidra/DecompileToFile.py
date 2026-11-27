# -*- coding: utf-8 -*-
# Ghidra Jython 脚本：把当前程序里所有函数的反编译伪代码导出为 .c 文件
#
# 由 rf.api.ghidra_decompile() 通过 analyzeHeadless 的 -postScript 调用。
# 参数：args[0] = 输出目录
#
# 注意：这是 Jython 2.x 语法（Ghidra 内置），不是 Python 3。
# 不要在这里用 f-string / print() 之外的新语法。

import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

out_dir = "/tmp/decompiled"
args = getScriptArgs()
if args and len(args) > 0:
    out_dir = args[0]

if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

prog = currentProgram
print("目标程序: %s" % prog.getName())

dec = DecompInterface()
dec.openProgram(prog)
monitor = ConsoleTaskMonitor()

fm = prog.getFunctionManager()
total = fm.getFunctionCount()
print("函数总数: %d" % total)

count = 0
failed = 0
for fn in fm.getFunctions(True):
    try:
        res = dec.decompileFunction(fn, 60, monitor)
        if res is None or not res.decompileCompleted():
            failed += 1
            continue
        code = res.getDecompiledFunction().getC()
        name = fn.getName()
        # 文件名清洗：Ghidra 函数名可能带 :: 或非法字符
        safe = name
        for ch in ['\\', '/', ':', '*', '?', '"', '<', '>', '|', ' ']:
            safe = safe.replace(ch, '_')
        path = os.path.join(out_dir, safe + ".c")
        f = open(path, "w")
        try:
            f.write("// 函数: " + name + "\n")
            f.write("// 入口: " + str(fn.getEntryPoint()) + "\n")
            f.write("// 参数: " + str(fn.getParameterCount()) + "\n\n")
            f.write(code)
        finally:
            f.close()
        count += 1
    except Exception as e:
        failed += 1
        print("!! %s: %s" % (fn.getName(), str(e)))

print("导出完成: %d 个函数，失败 %d 个 → %s" % (count, failed, out_dir))
