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
    def __init__(self, filepath:str, buffer_size:int=104857600):
        self.filepath = filepath
        self.buffer_size = buffer_size # default is 100mb
        self.filename_temp = f"""{''.join(
            [random.choice((string.ascii_letters + string.digits)) for _ in range(16)]
        )}.sol_file"""
        self.cleanup()  # Delete temp file as a precaution

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

    #  make object json decode-able, thanks to pure magic
    def to_json(self):
        hash_sum = hashlib.sha256()
        compressor = zlib.compressobj()

        with open(self.filepath, "rb") as file, open(f"temp/{self.filename_temp}", "ab+") as temp_file:
            for chunk in iter(functools.partial(file.read, self.buffer_size), b""):
                hash_sum.update(chunk)
                temp_file.write(compressor.compress(chunk))
            temp_file.write(compressor.flush())

        return {
            "hash_value":hash_sum.hexdigest(),
            "file_name_temp":self.filename_temp
        }
