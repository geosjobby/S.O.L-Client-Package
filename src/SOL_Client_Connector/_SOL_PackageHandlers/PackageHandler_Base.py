# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json

# Custom Packages
from .._Base_Classes import BASE_PackageHandler_Base, STOP_Error

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class PackageHandler_Base(BASE_PackageHandler_Base):
    # ------------------------------------------------------------------------------------------------------------------
    # - Various methods -
    # ------------------------------------------------------------------------------------------------------------------
    def _buffer_size(self, object_size: int) -> int:
        match object_size:
            case int(a) if a < 1048576:  # up to 1mb
                return 10240  # buffer of 10kb
            case int(a) if 1048576 < a < 10485760:  # between 1mb and 10mb
                return 102400  # buffer of 100kb
            case int(a) if 10485760 < a < 10485760:  # between 10mb and 100mb
                return 1048576  # buffer of 1mb
            case int(a) if a > 10485760:
                return 1048560  # buffer of 10mb
            case _:
                raise self.error(5000)

    def cleanup(self) -> None:
        del self.connection
        del self.address

    def close(self) -> None:
        self.connection.close()

    # ------------------------------------------------------------------------------------------------------------------
    # - Connection waiting -
    # ------------------------------------------------------------------------------------------------------------------
    def wait_for_state(self, state: str) -> None:
        print("wait : " + state)
        data_received = self.connection.recv(1024).decode("utf_8")
        if data_received == "STOP":
            raise STOP_Error()
        elif data_received != state:
            raise self.error(5401, state, data_received)
        return None

    def wait_for_state_multiple(self, states: list) -> str:
        data_received = self.connection.recv(1024).decode("utf_8")
        if data_received == "STOP":
            raise STOP_Error()
        elif data_received not in states:
            raise self.error(5401, states, data_received)
        return data_received

    def send_state(self, state: str) -> None:
        print("send : " + state)
        self.connection.send(state.encode("utf_8"))

    # ------------------------------------------------------------------------------------------------------------------
    # - Form parameters -
    # ------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def package_data(package_dict: dict) -> bytes:
        return json.dumps(package_dict).encode("utf_8")

    # ------------------------------------------------------------------------------------------------------------------
    # - Default Packages outgoing -
    # ------------------------------------------------------------------------------------------------------------------
    def _package_out(self, state:str, package_parameters:bytes, package_data:bytes)->None:
        # Send parameters
        self.send_state(f"{state}_PARAM")
        self.wait_for_state(f"READY")
        self.connection.sendall(package_parameters)
        self.wait_for_state(f"INGESTED")

        # Send package
        self.send_state(f"{state}_DATA")
        self.wait_for_state(f"READY")
        self.connection.sendall(package_data)
        self.wait_for_state(f"INGESTED")