# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import os
import functools
import string
import zlib
import hashlib
import pathlib
import random
import math

# Custom Packages
from .._Base_Classes import SOL_Error, BASE_Sol_File

# ----------------------------------------------------------------------------------------------------------------------
# - SOL File Object -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_File(BASE_Sol_File):
    def __init__(self, filepath:str,compression:int=9):
        self.hash_value = ""
        file_name_random = ''.join([random.choice((string.ascii_letters + string.digits)) for _ in range(16)])
        self.filename_transmission = f"""{file_name_random}.sol_file"""
        self.filename_temp = f"""{file_name_random}.temp"""
        self.cleanup()  # Delete temp file as a precaution, (theoretically it shouldn't exsist but you never know)
        self.filepath = filepath
        self.compression_level=compression if 0 <= compression < 10 else 9

    @property
    def filepath(self) -> str:
        return self._filepath

    @filepath.setter
    def filepath(self, filepath:str):
        if not os.path.isfile(filepath):
            raise SOL_Error(4406, "file is not found at path")
        self._filename = pathlib.Path(filepath).name
        self._filepath = filepath

    def cleanup(self) -> None:
        if pathlib.Path(f"temp/{self.filename_temp}").exists():
            os.remove(f"temp/{self.filename_temp}")
        if pathlib.Path(f"temp/{self.filename_transmission}").exists():
            os.remove(f"temp/{self.filename_transmission}")

    #  make object json decode-able, thanks to pure magic
    def to_json(self) -> str:
        return self.filename_temp

    # get buffer size
    def _buffer_size(self, object_size:int) -> int:
        match object_size:
            case int(a) if a < 1048576:  # up to 1mb
                return 10240  # buffer of 10kb
            case int(a) if 1048576 < a < 10485760:  # between 1mb and 10mb
                return 102400  # buffer of 100kb
            case int(a) if 10485760 < a < 10485760:  # between 10mb and 100mb
                return 1048576  # buffer of 1mb
            case int(a) if a > 10485760:
                return 1048560  # buffer of 10mb

    # compression function
    def compress_and_hash(self)->None:
        hash_sum = hashlib.sha256()
        compressor = zlib.compressobj(self.compression_level)
        buffer_size = self._buffer_size(os.path.getsize(self.filepath))
        total_chunks = math.ceil(os.path.getsize(self.filepath) / buffer_size)
        n = 0

        with open(self.filepath, "rb") as file, open(f"temp/{self.filename_temp}", "ab+") as temp_file:
            for chunk in iter(functools.partial(
                    file.read,
                    buffer_size
            ), b""):
                n += 1
                hash_sum.update(chunk)
                temp_file.write(compressor.compress(chunk))
                print(n, total_chunks)
            temp_file.write(compressor.flush())
        self.hash_value = hash_sum.hexdigest()
        print("here")
