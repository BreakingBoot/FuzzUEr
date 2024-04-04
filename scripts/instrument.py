import shutil
import os
import argparse

def copy(src, dir, file, dst, is_file=True, override=False):
    src_path = os.path.join(src, file)
    dst_path = os.path.join(dir, dst, file)

    if os.path.exists(dst_path) and not override:
        print(f"File '{file}' already exists in '{dst}', skipping copy.")
        return

    if is_file:
        shutil.copy2(src_path, dst_path)
    else:
        shutil.copytree(src_path, dst_path)
    
def asan_instrumetation(src, dir):
    # copy the source files to their corrsponding directories
    copy(src, dir, 'Asan.h', 'MdeModulePkg/Include/Library')
    copy(src, dir, 'AsanInfo.h', 'MdeModulePkg/Include/Guid')

    # copy the folders to their corresponding directories
    copy(src, dir, 'AsanLib', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanLibNull', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanRuntimeLib', 'MdeModulePkg/Library/', False)
    copy(src, dir, 'AsanMemoryLib', 'MdePkg/Library/', False)
    copy(src, dir, 'AsanMemoryLibRepStr', 'MdePkg/Library/', False)

    # apply the patch file in src to the entire dst dir
    patch_path = os.path.join(src, 'asan.patch')
    os.system('patch -p1 -d ' + dir + ' < ' + patch_path + ' --binary')


def main():
    parser = argparse.ArgumentParser(description='Instrument the UEFI firmware with AddressSanitizer.')
    parser.add_argument('-s', '--src', type=str, required=True, help='The path to the UEFI firmware source.')
    parser.add_argument('-d', '--dst', type=str, required=True, help='The path to the UEFI firmware destination.')
    args = parser.parse_args()
    asan_instrumetation(args.src, args.dst)

if __name__ == '__main__':
    main()