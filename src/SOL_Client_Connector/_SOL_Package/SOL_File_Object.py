# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json
import os
import base64
import zlib

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
        with open(self.filepath, "rb") as file:
            data_encoded = base64.b64encode(
                zlib.compress(file.read(), zlib.Z_BEST_COMPRESSION)
            ).decode("utf_8")
        return data_encoded