# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import os
import base64
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
    def __init__(self, filepath: str):
        self.filepath = filepath

    @property
    def filepath(self):
        return self._filepath

    @filepath.setter
    def filepath(self, filepath:str):
        if os.path.isfile(filepath):
            self._filename = pathlib.Path(filepath).name
            self._filepath = filepath
        else:
            raise SOL_Error(4406, "file is not found at path")

    #  make object json decode-able
    def to_json(self):
        self.filename_temp = "".join([random.choice((string.ascii_letters + string.digits)) for _ in range(12)])
        # buffer_size = 1073741824 # 1gb
        # buffer_size = 104857600 # 100mb
        buffer_size = 10485760 # 10mb
        # buffer_size = 1048576 # 1mb
        hash_sum = hashlib.sha256()
        compressor = zlib.compressobj() # set together to mark this in my brain as stuck together

        # Delete temp file
        if pathlib.Path(f"temp/{self.filename}").exists():
            os.remove(f"temp/{self.filename}")

        with open(self.filepath, "rb") as file, open(f"temp/{self.filename_temp}", "ab+") as temp_file:
            # Buffer for large file sizes
            file_data = file.read(buffer_size)
            n = 0
            while file_data:
                hash_sum.update(file_data)
                temp_file.write(compressor.compress(file_data))
                file_data = file.read(buffer_size) # prepare for next loop
                n+=1
                print(n)
            temp_file.write(compressor.flush())

        return {
            "hash_value":hash_sum.hexdigest(),
            "file_name_temp":self.filename_temp
        }
