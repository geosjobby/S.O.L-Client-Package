# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import sys
from Crypto.PublicKey.RSA import RsaKey
import json
import base64

# Custom Packages
from .._Base_Classes import BASE_PackageHandler_Data
from .PackageHandler_Base import PackageHandler_Base
from ..SOL_Encryption import *

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class PackageHandler_Data(PackageHandler_Base,BASE_PackageHandler_Data):
    # ------------------------------------------------------------------------------------------------------------------
    # - Form parameters -
    # ------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def package_parameters(
            session_key_encrypted:bytes=None,
            tag:bytes=None,
            nonce:bytes=None,
            package_length:int=None
    ) -> bytes:
        return json.dumps({
            "sske": base64.b64encode(session_key_encrypted).decode("utf8") if session_key_encrypted is not None else None,
            "tag": base64.b64encode(tag).decode("utf8") if tag is not None else None,
            "nonce": base64.b64encode(nonce).decode("utf8") if nonce is not None else None,
            "len": package_length if package_length is not None else None,
        }).encode("utf8")

    # ------------------------------------------------------------------------------------------------------------------
    # - Packages outgoing -
    # ------------------------------------------------------------------------------------------------------------------
    def package_output_plain(self, state: str, package_dict: dict) -> None:
        # assemble the package bytes
        package_data = self.package_data(package_dict)
        # Encrypt package
        # /
        # assemble package parameters
        package_parameters =  self.package_parameters(None,None,None,sys.getsizeof(package_data))
        # send the data
        self._package_out(state, package_parameters, package_data)

    def package_output_encrypted(self, state:str, package_dict:dict, server_public_key:RsaKey) -> None:
        # assemble the package bytes
        package_data = self.package_data(package_dict)
        # Encrypt package
        encrypted_package, session_key_encrypted, tag, nonce = pp_encrypt(
            package_data,
            server_public_key
        )
        # assemble package parameters
        package_parameters = self.package_parameters(
            session_key_encrypted,
            tag,
            nonce,
            sys.getsizeof(encrypted_package)
        )
        # send the data
        self._package_out(state, package_parameters, encrypted_package)

    # ------------------------------------------------------------------------------------------------------------------
    # - Default Packages incoming -
    # ------------------------------------------------------------------------------------------------------------------
    def package_input(self, state:str, client_private_key:RsaKey) -> dict:
        self.wait_for_state(f"{state}_PARAM")
        self.send_state(f"{state}_PARAM_READY")
        package_param_dict = json.loads(self.connection.recv(10240).decode("utf_8"))
        match package_param_dict:

            # unencrypted package
            case {"sske": None,"tag": None,"nonce": None,"len": int(package_length)}:
                # Ingest all the parameters
                self.send_state(f"{state}_PARAM_INGESTED")

                # Ingest the package
                package_data = b""
                while sys.getsizeof(package_data) < package_length:
                    package_data += self.connection.recv(1048576)
                self.send_state(f"{state}_PACKAGE_INGESTED")

                # Decrypt the package
                # /

            # encrypted package
            case {"sske": str(sske),"tag": str(tag),"nonce": str(nonce),"len": int(package_length)}:
                # Ingest all the parameters
                session_key_encrypted = base64.b64decode(sske.encode("utf8"))
                tag = base64.b64decode(tag.encode("utf8"))
                nonce = base64.b64decode(nonce.encode("utf8"))
                self.send_state(f"{state}_PARAM_INGESTED")

                # Ingest the package
                package_data_encrypted = b""
                while sys.getsizeof(package_data_encrypted) < package_length:
                    package_data_encrypted += self.connection.recv(1048576)
                self.send_state(f"{state}_PACKAGE_INGESTED")

                # Decrypt the package
                package_data = pp_decrypt(
                    package_data_encrypted,
                    client_private_key,
                    session_key_encrypted,
                    tag,
                    nonce
                )

            # if the param package was not setup correctly
            case _:
                raise self.error(5401)

        # Decode the package
        package_dict = json.loads(package_data.decode("utf_8"))
        return package_dict
