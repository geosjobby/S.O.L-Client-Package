# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import os.path
import zlib
import hashlib
from Crypto.PublicKey.RSA import RsaKey
import json
import base64
import functools
import math


# Custom Packages
from .._Base_Classes import BASE_PackageHandler_File, BASE_Sol_File
from .PackageHandler_Base import PackageHandler_Base
from ..SOL_Encryption import *

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class PackageHandler_File(PackageHandler_Base,BASE_PackageHandler_File):
    # ------------------------------------------------------------------------------------------------------------------
    # - Handle file transformation in chunks -
    # ------------------------------------------------------------------------------------------------------------------
    def _file_package_handle_chunk(
            self,
            filepath_1:str,
            filepath_2:str,
            function_, # function to use
            file_handling_section:str
    ) -> None:
        file_size_1 = os.path.getsize(filepath_1)
        file_size_2 = os.path.getsize(filepath_1)
        buffer_size = self._buffer_size(file_size_1)
        total_chunks = math.ceil(file_size_1 / self._buffer_size(file_size_2))
        with open(filepath_1, "rb") as file_1, open(filepath_2, "ab+") as file_2:
            for _, chunk in enumerate(iter(functools.partial(file_1.read, buffer_size), b"")):
                file_2.write(function_(chunk))

    # ------------------------------------------------------------------------------------------------------------------
    # - Form parameters -
    # ------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def file_package_parameters(
            session_key_encrypted: bytes = None,
            nonce: bytes = None,
            package_length: int = None,
            filename: str = None,
            hash_value: str = None
    ) -> bytes:
        return json.dumps({
            "sske": base64.b64encode(session_key_encrypted).decode(
                "utf8") if session_key_encrypted is not None else None,
            "nonce": base64.b64encode(nonce).decode("utf8") if nonce is not None else None,
            "len": package_length if package_length is not None else None,
            "file_name": base64.b64encode(filename.encode("utf8")).decode("utf8") if filename is not None else None,
            "hash_value": base64.b64encode(hash_value.encode("utf8")).decode(
                "utf8") if hash_value is not None else None,
        }).encode("utf8")

    # ------------------------------------------------------------------------------------------------------------------
    # - FILE Packages outgoing -
    # ------------------------------------------------------------------------------------------------------------------
    def file_package_output(self, state: str, file_object: BASE_Sol_File, server_public_key: RsaKey) -> None:
        # Not needed in client as the client compresses the files before connecting to the API server
        # # compress the file, which also creates the hash value
        # file_object.compress_and_hash()

        # Encrypt File
        session_key_encrypted, nonce, cipher_aes = pp_cipher_aes_encryptor(server_public_key)
        self._file_package_handle_chunk(
            filepath_1=f"temp/{file_object.filename_temp}",
            filepath_2=f"temp/{file_object.filename_transmission}",
            function_=cipher_aes.encrypt,
            file_handling_section="ENCRYPTED"
        )

        # assemble package parameters
        package_parameters = self.file_package_parameters(
            session_key_encrypted,
            nonce,
            os.path.getsize(f"temp/{file_object.filename_transmission}"),
            file_object.filename_transmission,
            file_object.hash_value
        )

        # Send parameters
        self.send_state(f"{state}_PARAM")
        self.wait_for_state(f"{state}_PARAM_READY")
        self.connection.sendall(package_parameters)
        self.wait_for_state(f"{state}_PARAM_INGESTED")

        # send the file in chunks
        buffer_size = self._buffer_size(os.path.getsize(f"temp/{file_object.filename_transmission}"))
        file_size = os.path.getsize(f"temp/{file_object.filename_transmission}")
        total_chunks = math.ceil(file_size / self._buffer_size(file_size))
        with open(f"temp/{file_object.filename_transmission}", "rb") as file_final_:
            for _, chunk in enumerate(iter(functools.partial(file_final_.read, buffer_size), b"")):
                self.connection.send(chunk)
        del total_chunks, buffer_size, file_size

        # wait for ingestion to finish
        self.wait_for_state(f"{state}_PACKAGE_INGESTED")

        # wait for file decompression and check to happen
        self.wait_for_state(f"{state}_CHECKED")

    # ------------------------------------------------------------------------------------------------------------------
    # - FILE Packages incoming -
    # ------------------------------------------------------------------------------------------------------------------
    def file_package_input(self, state: str, client_private_key: RsaKey) -> None:
        self.wait_for_state(f"{state}_PARAM")
        self.send_state(f"{state}_PARAM_READY")
        try:
            package_param_dict = json.loads(self.connection.recv(1024).decode("utf_8"))
            session_key_encrypted = base64.b64decode(package_param_dict["sske"].encode("utf8"))
            nonce = base64.b64decode(package_param_dict["nonce"].encode("utf8"))
            package_length = int(package_param_dict["len"])
            file_name = base64.b64decode(package_param_dict["file_name"].encode("utf8")).decode("utf_8")
            hash_value = base64.b64decode(package_param_dict["hash_value"].encode("utf8")).decode("utf_8")
            file_path = f"temp/{file_name}"
        except KeyError:
            raise self.error(5401)

        self.send_state(f"{state}_PARAM_INGESTED")

        # get the buffer size
        buffer_size = self._buffer_size(package_length)

        # Ingest the file
        total_size = 0
        with open(f"{file_path}.temp", "ab+") as temp_file:
            while os.path.getsize(f"{file_path}.temp") < package_length:
                chunk = self.connection.recv(buffer_size)
                temp_file.write(chunk)
                total_size += len(chunk)
        del total_size, chunk
        self.send_state(f"{state}_PACKAGE_INGESTED")

        # Decrypt the package
        cipher_aes = pp_cipher_aes_decryptor(client_private_key, session_key_encrypted, nonce)
        self._file_package_handle_chunk(
            filepath_1=f"{file_path}.temp",
            filepath_2=f"{file_path}.temp2",
            function_=cipher_aes.decrypt,
            file_handling_section="DECRYPTED"
        )

        # delete temp file
        os.remove(f"{file_path}.temp")

        # Decompress file
        decompressor = zlib.decompressobj()
        self._file_package_handle_chunk(
            filepath_1=f"{file_path}.temp2",
            filepath_2=file_path,
            function_=decompressor.decompress,
            file_handling_section="DECOMPRESSED"
        )
        # delete temp file
        os.remove(f"{file_path}.temp2")

        # check hash_sum in chunks
        hash_sum = hashlib.sha256()

        file_size = os.path.getsize(f"{file_path}")
        total_chunks = math.ceil(file_size / self._buffer_size(file_size))
        with open(file_path, "rb") as file_final_:
            for _, chunk in enumerate(iter(functools.partial(file_final_.read, buffer_size), b"")):
                hash_sum.update(chunk)

        del total_chunks

        if hash_sum.hexdigest() != hash_value:
            os.remove(f"{file_path}")  # delete file if hash wasn't correct
            raise self.error(5402)

        # send correct state
        self.send_state(f"{state}_CHECKED")
