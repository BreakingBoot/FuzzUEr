'''
Description:
	Asan log check script
Version:
	v0.6
Date:
	20170526
'''
#!/usr/bin/python
#coding:utf-8

import os.path
import sys
import re

DEBUG_MODE = 0
STACK_NUMBER = 9
# get input file name
Arglen = len(sys.argv)
if (Arglen > 2):
    try:
        InFileHandle = open(sys.argv[1], 'r')
    except FileNotFoundError:
        print("Error!!!\nPlease input one VALID file name.")
        exit(0)
else:
    print("Usage:")
    print("AsanLogCheck [File] [Path1]|[Path2]...[PathN]")
    print("    File: Input file name.")
    print("    PathN: Debug symbol path.")
    print("Example:")
    print("python AsanLogCheck.py abc.log ~/work/edk2/Build/AbcPkgX64/DEBUG_CLANG50/ ~/work2/edk2/Build/AbcPkgX64/DEBUG_CLANG50/\n")
    exit(0)

# open output/temporal files
T1FileHandle = open('T1.txt', 'w+')
T2FileHandle = open('T2.txt', 'w+')
T3FileHandle = open('T3.txt', 'w+')

# get input file length
ilength = len(InFileHandle.readlines())
InFileHandle.seek(0)

# check valid info and save them to temporal files
for i in range(0, ilength):
    str1 = InFileHandle.readline()
    if str1.find("fail!")!= -1:
        str1 = str1[-25:]
        T1FileHandle.writelines(str1)
        for j in range(0, STACK_NUMBER):
            str1 = InFileHandle.readline()
            if str1.find("asan")!= -1:
                str1 = InFileHandle.readline()
            str1 = str1.lstrip('Return IP address is ')
            T1FileHandle.writelines(str1)
    if str1.find("Loading driver at") != -1:
        str2 = str1[56:-2] + '\n'
        str1 = str1[18:31]
        str1 = str1 + str2
        T2FileHandle.writelines(str1)
    if str1.find("Loading DXE CORE at") != -1:
        str2 = " DxeCore.efi\n"
        str1 = str1[20:33]
        str1 = str1 + str2
        T2FileHandle.writelines(str1)
    if str1.find("Loading SMM driver at") != -1:
        str2 = str1[60:-2] + '\n'
        str1 = str1[22:35]
        str1 = str1 + str2
        T2FileHandle.writelines(str1)
    if str1.find("SMM IPL loading SMM Core at") != -1:
        str2 = " PiSmmCore.efi\n"
        str1 = "0x000" + str1[-10:-2]
        str1 = str1 + str2
        T2FileHandle.writelines(str1)

# get T1.txt file length
T1FileHandle.seek(0)
t1length = len(T1FileHandle.readlines())
T1FileHandle.seek(0)
# get T2.txt file length
T2FileHandle.seek(0)
t2length = len(T2FileHandle.readlines())

for i in range(0, t1length):
    # get address from T1.txt
    str1 = T1FileHandle.readline()
    str1 = str1.rstrip('\n')
    try:
        addr1 = int(str1, 16)
    except ValueError:
        continue
    temp = addr1
    drvname = 'NULL'
    T2FileHandle.seek(0)

    for j in range(0, t2length):
        # get address from T2.txt
        str2 = T2FileHandle.readline()
        addr2 = int(str2[0:13], 16)
        # subtract and get the minor value
        if(addr1 > addr2):
            if(temp > (addr1 - addr2)):
                temp = addr1 - addr2
                drvname = str2[14:]
                drvname = drvname.rstrip('\n')
                # replace '.efi' as '.debug'
                strinfo = re.compile('.efi')
                drvname = strinfo.sub('.debug', drvname)
                PathNumber = Arglen - 2
                PathIndex = 2
                while(PathNumber > 0):
                    rootdir = sys.argv[PathIndex]
                    for (dirpath, dirnames, filenames) in os.walk(rootdir):
                        for filename in filenames:
                            if (filename == drvname):
                                drvname = os.path.join(dirpath, filename)
                    PathNumber -= 1
                    PathIndex += 1

    T3FileHandle.writelines(drvname + ' ')
    T3FileHandle.writelines(str(temp) + '\n')

T3FileHandle.close()

os.system('llvm-symbolizer < T3.txt > Output.txt')

OutFileHandle = open('Output.txt', 'r')
olength = len(OutFileHandle.readlines())
OutFileHandle.seek(0)
T1FileHandle.seek(0)
str1 = T1FileHandle.readline()
str1 = str1[:-2]
# display the string in middle
slength = len(str1)
if slength < 80:
    slength = (80 - slength) / 2
else:
    slength = 0
for i in range(0, slength):
    str1 = '-' + str1
for i in range(0, slength):
    str1 += '-'
str1 += '\n' + OutFileHandle.readline()
x = 0
for i in range(2, olength):
    str2 = OutFileHandle.readline()
    try:
        int(str2, 16)
        str1 += str2 + str2 + '\n'
        x += 2
    except ValueError:
        str1 += str2
    if (i + x) % (STACK_NUMBER * 3) == 0:
        while(True):
            str2 = T1FileHandle.readline()
            try:
                int(str2,16)
            except ValueError:
                str2 = str2[:-2]
                for j in range(0, slength):
                    str2 = '-' + str2
                for j in range(0, slength):
                    str2 += '-'
                str2 += '\n'
                break
        str1 += str2
OutFileHandle = open('Output.txt', 'w')
OutFileHandle.writelines(str1)

InFileHandle.close()
T1FileHandle.close()
T2FileHandle.close()
OutFileHandle.close()

# delete temporal files
if (DEBUG_MODE == 0):
    os.remove('T1.txt')
    os.remove('T2.txt')
    os.remove('T3.txt')

print('Done!')
