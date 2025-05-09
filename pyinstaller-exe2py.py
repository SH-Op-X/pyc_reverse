import os
import re
import sys
import zlib
import struct
import argparse
import subprocess
from uuid import uuid4 as uniquename

from Crypto.Cipher import AES
from Crypto.Util import Counter

from xdis.unmarshal import load_code

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def pycHeader2Magic(header):
    header = bytearray(header)
    magicNumber = bytearray(header[:2])
    return magicNumber[1] << 8 | magicNumber[0]

tmp_path = os.getcwd()

class CTOCEntry:
    def __init__(
        self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name
    ):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b"\0" * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed
        self.cryptoKey = None
        self.cryptoKeyFileData = None
        self.possible_entries = []

    def open(self):
        try:
            self.fPtr = open(self.filePath, "rb")
            self.fileSize = os.stat(self.filePath).st_size
        except:
            eprint("[!] Error: Could not open {0}".format(self.filePath))
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        print("[+] Processing {0}".format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            eprint("[!] Error: File is too short or truncated")
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            eprint(
                "[!] Error: Missing cookie, unsupported pyinstaller version or not a pyinstaller archive"
            )
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b"python" in self.fPtr.read(64).lower():
            print("[+] Pyinstaller version: 2.1+")
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            print("[+] Pyinstaller version: 2.0")

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack(
                    "!8siiii", self.fPtr.read(self.PYINST20_COOKIE_SIZE)
                )

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack(
                    "!8sIIii64s", self.fPtr.read(self.PYINST21_COOKIE_SIZE)
                )

        except:
            eprint("[!] Error: The file is not a pyinstaller archive")
            return False

        self.pymaj, self.pymin = (
            (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        )
        print("[+] Python version: {0}.{1}".format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = (
            self.fileSize
            - self.cookiePos
            - (
                self.PYINST20_COOKIE_SIZE
                if self.pyinstVer == 20
                else self.PYINST21_COOKIE_SIZE
            )
        )

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print("[+] Length of package: {0} bytes".format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize,) = struct.unpack("!i", self.fPtr.read(4))
            nameLen = struct.calcsize("!iIIIBc")    # 18

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                name,
            ) = struct.unpack(
                "!IIIBc{0}s".format(entrySize - nameLen), self.fPtr.read(entrySize - 4)
            )

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                print('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                print(
                    "[!] Warning: Found an unamed file in CArchive. Using random name {0}".format(
                        name
                    )
                )

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name,
                )
            )

            parsedLen += entrySize
        print("[+] Found {0} files in CArchive".format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = (
            filepath.replace("\\", os.path.sep)
            .replace("/", os.path.sep)
            .replace("..", "__")
        )
        nmDir = os.path.dirname(nm)
        if nmDir != "" and not os.path.exists(
            nmDir
        ):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, "wb") as f:
            f.write(data)

    def extractFiles(self):
        print("[+] Beginning extraction...please standby")
        extractionDir = self.filePath + "_extracted"

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b"d" or entry.typeCmprsData == b"o":
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != "":
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b"s":
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts, sometimes the name of exe may not be the actual main file name when using pyinstaller to pack.
                print("[+] Possible entry point: {0}.pyc".format(entry.name))
                self.possible_entries.append(entry.name)
                if self.pycMagic == b"\0" * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + ".pyc")
                self._writePyc(entry.name + ".pyc", data)

            elif entry.typeCmprsData == b"M" or entry.typeCmprsData == b"m":
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b"\r\n":
                    # < pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        print(
                            "[+] Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a pyc file with a header (8,12, or 16 bytes)
                        # Extract the code object after the header
                        self.cryptoKeyFileData = self._extractCryptoKeyObject(data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + ".pyc")

                    self._writePyc(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        print(
                            "[+] Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a plain code object without a header
                        self.cryptoKeyFileData = data

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b"z" or entry.typeCmprsData == b"Z":
                    self._extractPyz(entry.name)   # different with pyinstxtractor

        # Fix bare pyc's if any
        self._fixBarePycs()


    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, "r+b") as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _extractCryptoKeyObject(self, data):
        if self.pymaj >= 3 and self.pymin >= 7:
            # 16 byte header for 3.7 and above
            return data[16:]
        elif self.pymaj >= 3 and self.pymin >= 3:
            # 12 byte header for 3.3-3.6
            return data[12:]
        else:
            # 8 byte header for 2.x, 3.0-3.2
            return data[8:]

    def _writePyc(self, filename, data):
        with open(filename, "wb") as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b"\0" * 4)  # Bitfield
                pycFile.write(b"\0" * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b"\0" * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b"\0" * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _getCryptoKey(self):
        if self.cryptoKey:
            return self.cryptoKey

        if not self.cryptoKeyFileData:
            return None

        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
        self.cryptoKey = co.co_consts[0]
        return self.cryptoKey

    def _tryDecrypt(self, ct, aes_mode):
        CRYPT_BLOCK_SIZE = 16

        key = bytes(self._getCryptoKey(), "utf-8")
        assert len(key) == 16

        # Initialization vector
        iv = ct[:CRYPT_BLOCK_SIZE]

        if aes_mode == "ctr":
            # Pyinstaller >= 4.0 uses AES in CTR mode
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])

        elif aes_mode == "cfb":
            # Pyinstaller < 4.0 uses AES in CFB mode
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])            

    def _extractPyz(self, name):
        dirName = "."

        with open(name, "rb") as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b"PYZ\0"  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b"\0" * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print(
                    "[!] Warning: pyc magic of files inside PYZ archive are different from those in CArchive"
                )

            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = load_code(f, pycHeader2Magic(pyzPycMagic))
            except:
                print(
                    "[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.".format(
                        name
                    )
                )
                return

            print("[+] Found {0} files in PYZ archive".format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode("utf-8")
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace("..", "__").replace(".", os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, "__init__.pyc")

                else:
                    filePath = os.path.join(dirName, fileName + ".pyc")

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    try:
                        # Automatic decryption
                        # Make a copy
                        data_copy = data

                        # Try CTR mode, Pyinstaller >= 4.0 uses AES in CTR mode
                        data = self._tryDecrypt(data, "ctr")
                        data = zlib.decompress(data)
                    except:
                        # Try CFB mode, Pyinstaller < 4.0 uses AES in CFB mode
                        try:
                            data = data_copy
                            data = self._tryDecrypt(data, "cfb")
                            data = zlib.decompress(data)
                        except:
                            eprint(
                                "[!] Error: Failed to decrypt & decompress {0}. Extracting as is.".format(
                                    filePath
                                )
                            )
                            open(filePath + ".encrypted", "wb").write(data_copy)
                            continue
                
                self._writePyc(filePath, data)

# Add
IMPORT_RE = re.compile(r'^\s*import\s+(.*)\s*$')
FROM_IMPORT_RE = re.compile(r'^\s*from\s+([\w.]+)\s+import\s+.*$')
def extract_top_level_imports(filepath):
    """
    提取 .py 文件开头部分的顶层库名。

    只查找直到遇到第一个非导入、非注释、非空白行。

    Args:
        filepath (str): 要读取的 .py 文件路径。

    Returns:
        set: 包含提取到的顶层库名的集合。
    """
    imported_libraries = set()

    try:
        # 使用 'utf-8' 编码打开文件，处理可能的编码问题
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()

                # 忽略空白行和注释行
                if not stripped_line or stripped_line.startswith('#'):
                    continue

                # 尝试匹配 import 语句
                import_match = IMPORT_RE.match(line)
                if import_match:
                    # 提取 import 后面的内容，可能包含多个库用逗号分隔
                    imported_parts = import_match.group(1)
                    # 分割逗号分隔的部分
                    for part in imported_parts.split(','):
                        part = part.strip()
                        if not part:
                            continue # 跳过空的分割结果

                        # 处理 'module as alias' 的情况，只取 module 部分
                        if ' as ' in part:
                            module_name = part.split(' as ')[0].strip()
                        else:
                            module_name = part.strip()

                        # 提取顶层库名 (例如 'package.module' 提取 'package')
                        top_level_name = module_name.split('.')[0]
                        if top_level_name:
                            imported_libraries.add(top_level_name)

                    # 如果是导入语句，继续查找下一行
                    continue

                # 尝试匹配 from ... import 语句
                from_import_match = FROM_IMPORT_RE.match(line)
                if from_import_match:
                    # 提取 from 后面的模块/包名 (例如 'package.module')
                    source_module = from_import_match.group(1)
                     # 提取顶层库名 (例如 'package.module' 提取 'package')
                    top_level_name = source_module.split('.')[0]
                    if top_level_name:
                        imported_libraries.add(top_level_name)
                    # 如果是导入语句，继续查找下一行
                    continue
                # 如果当前行不是导入语句、不是注释、不是空白行，
                # 那么认为已经离开了文件的导入部分，停止查找
                break
    except FileNotFoundError:
        eprint(f"[!] Error: File not found at {filepath}", file=sys.stderr)
    except Exception as e:
        eprint(f"[!] Error processing file {filepath}: {e}", file=sys.stderr)

    return list(imported_libraries)


def pyc2py(pyc_path, is_main=False):
    os.chdir(tmp_path)
    exe_path = "./pycdc.exe"
    command = [exe_path, pyc_path]
    # some decompiled pyc is incorrect (may face stack overflow problem, this is related to pycdc.exe), so try-except is used
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except Exception as e:
        print(f"Error: {e}")
        result = -1

    import_list = []
    if result == -1 or result.returncode != 0:
        eprint(f"[!] Error: Failed to decompile {pyc_path}.")
    else:
        if result.stdout:
            py_code = result.stdout
            if py_code[:2].encode() == b"\xff\xfe":
                py_code = py_code[2:]
            dir_path = os.path.dirname(pyc_path)
            name, _ = os.path.splitext(os.path.basename(pyc_path))
            py_path = os.path.join(dir_path, "..", name+".py")
            with open(py_path, "w", encoding="utf-8") as py_file:
                py_file.write(py_code)
            print(f"[+] Decompile {os.path.basename(pyc_path)} to {name}.py by pycdc.exe, please check it. (Notice: Output may not be correct)")
            if is_main:
                import_list = extract_top_level_imports(py_path)
        else:
            print(f"[+] Output is none.")
    return import_list


def find_pyc(arch, exe_path, ex_import):
    exe_name = os.path.basename(exe_path)
    main_pyc_name = exe_name.replace(".exe", ".pyc")
    pyc_path = os.path.join(exe_path+ "_extracted", main_pyc_name)
    print(f"[+] Starting decompile {main_pyc_name} in exe...")
    if not os.path.exists(pyc_path):
        eprint(f"[!] Unable to find {main_pyc_name} in exe.")
        print(f"[+] Possible entry pyc are listed below: ")
        for i in range(len(arch.possible_entries)):
            print(f"**({i+1}) {arch.possible_entries[i]}")
        choice = input("[?] Enter choice: ")
        if choice not in [str(i+1) for i in range(len(arch.possible_entries))]:
            eprint(f"[!] Invalid choice!")
            return
        print(f"[+] Starting decompile {arch.possible_entries[int(choice)-1]} in exe...")
        import_list = pyc2py(os.path.join(exe_path + "_extracted", arch.possible_entries[int(choice)-1] + ".pyc"), is_main=True)
    else:
        import_list = pyc2py(pyc_path, is_main=True)
    if ex_import and len(import_list):
        print(f"[+] Find import lib: {' '.join(import_list)}.")
        print(f"[+] Starting decompile import pyc file in exe... ")
        for pyc_name in import_list:
            pyc_path = os.path.join(exe_path + "_extracted", pyc_name + ".pyc")
            if os.path.exists(pyc_path):
                pyc2py(pyc_path)



def main():
    parser = argparse.ArgumentParser(description="PyInstaller Extractor NG")
    parser.add_argument("filename", help="Path to the file to extract")
    parser.add_argument(
        "-i",
        "--ex_import",
        help="Decompile import lib pyc. It is suggested to use this option only when you find that the import lib needed to be decompiled and analysed.",
        action="store_true",
    )
    args = parser.parse_args()

    arch = PyInstArchive(args.filename)
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
                print(f"[+] Successfully extracted pyinstaller archive: {args.filename}")
                find_pyc(arch, args.filename, args.ex_import)
                sys.exit(0)

        arch.close()
    sys.exit(1)


if __name__ == "__main__":
    main()
