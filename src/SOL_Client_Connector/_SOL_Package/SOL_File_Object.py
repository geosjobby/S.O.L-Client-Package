# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json
import os
import base64
import zlib
import hashlib

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
            self._filepath = filepath
        else:
            raise SOL_Error(4406, "file is not found at path")

    #  make object json decode-able
    def to_json(self):
        buffer_size = 1048576 # 1mb
        hash_sum = hashlib.sha256()
        c, compressor = b'', zlib.compressobj() # set together to mark this in my brain as stuck together
        with open(self.filepath, "rb") as file:
            file_data = file.read(buffer_size)
            while file_data: # Buffer for large file sizes
                hash_sum.update(file_data)
                c = c + compressor.compress(file_data)
                # prepare for next loop
                file_data = file.read(buffer_size)

            hash_value = hash_sum.hexdigest()
            data_compressed = c + compressor.flush()

            data_string = base64.b64encode(data_compressed).decode("utf_8")
        return {"hash_value":hash_value, "bytes_encoded":data_string}