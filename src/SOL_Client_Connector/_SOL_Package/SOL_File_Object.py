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

# Custom Packages
from .._Base_Classes import SOL_Error, SOL_File_Base

# ----------------------------------------------------------------------------------------------------------------------
# - SOL File Object -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_File(SOL_File_Base):
    def __init__(self, filepath:str):
        self.hash_value = ""
        file_name_random = ''.join([random.choice((string.ascii_letters + string.digits)) for _ in range(16)])
        self.filename_transmission = f"""{file_name_random}.sol_file"""
        self.filename_temp = f"""{file_name_random}.temp"""
        self.cleanup()  # Delete temp file as a precaution, (theoretically it shouldn't exsist but you never know)
        self.filepath = filepath

    @property
    def filepath(self):
        return self._filepath

    @filepath.setter
    def filepath(self, filepath:str):
        if not os.path.isfile(filepath):
            raise SOL_Error(4406, "file is not found at path")
        self._filename = pathlib.Path(filepath).name
        self._filepath = filepath

    def cleanup(self):
        if pathlib.Path(f"temp/{self.filename_temp}").exists():
            os.remove(f"temp/{self.filename_temp}")
        if pathlib.Path(f"temp/{self.filename_transmission}").exists():
            os.remove(f"temp/{self.filename_transmission}")

    #  make object json decode-able, thanks to pure magic
    def to_json(self):
        return self.filename_temp

    # get buffer size
    def _buffer_size(self, object_size:int):
        match object_size:
            case int(a) if a < 1048576:  # up to 1mb
                return 102400  # buffer of 100kb
            case int(a) if 1048576 < a < 10485760:  # between 1mb and 10mb
                return 1048576  # buffer of 1mb
            case int(a) if 10485760 < a < 10485760:  # between 10mb and 100mb
                return 10485760  # buffer of 10mb
            case int(a) if a > 10485760:
                return 10485600  # buffer of 100mb

    # compression function
    def compress(self):
        hash_sum = hashlib.sha256()
        compressor = zlib.compressobj(zlib.Z_BEST_COMPRESSION)

        with open(self.filepath, "rb") as file, open(f"temp/{self.filename_temp}", "ab+") as temp_file:
            for chunk in iter(functools.partial(
                    file.read,
                    self._buffer_size(os.path.getsize(self.filepath))
            ), b""):
                hash_sum.update(chunk)
                temp_file.write(compressor.compress(chunk))
            temp_file.write(compressor.flush())

        self.hash_value = hash_sum.hexdigest()
