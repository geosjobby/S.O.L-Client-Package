# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages

# Custom Packages
from .._Base_Classes import SOL_Package_Base, SOL_Error, BASE_SOL_Credentials
from .._SOL_File import SOL_File
from .._SOL_Credentials import SOL_Credentials

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package(SOL_Package_Base):
    def __init__(self, api_key:str=None):
        # Set default var
        self._commands = []
        self._file_list = []
        self._credentials = None

        # Check if immediate input was given
        if api_key is not None:
            self.api_key = api_key

    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value:str):
        if not isinstance(value, str) \
        or len(value) != self.api_key_length:
            raise SOL_Error(4405, "API key was incorrectly defined")
        self._api_key = value
    @property
    def commands(self) -> list:
        return self._commands
    @property
    def file_list(self) -> list[SOL_File]:
        return self._file_list
    @property
    def credentials(self) -> BASE_SOL_Credentials:
        return self._credentials

    # ------------------------------------------------------------------------------------------------------------------
    # - Command List Formation -
    # ------------------------------------------------------------------------------------------------------------------
    def command_add(self,*args:dict) -> None:
        if not all((len(c) == 1 and isinstance(c, dict)) for c in args):
            raise SOL_Error(4406, "Unable to insert the command(s)")
        self._commands = self.commands + list(args)

        # check for file presence
        for c in list(args):
            self._iterateRecursion(c)

    def _iterateRecursion(self, dict_object: dict) -> None:
        for _, v in dict_object.items():
            match v:
                case SOL_File():
                    self._file_list.append(v)
                case dict():
                    self._iterateRecursion(v) # the few times in a year that I use recursion
                case SOL_Credentials():
                    if self.credentials is not None:
                        if id(self.credentials) != id(v):
                            raise SOL_Error(4407, "Only one unique set of credentials can be stored within the conversation")
                    else:
                        self._credentials = v

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------
    def pre_check(self) -> None:
        # Check if we can form package
        if self.api_key is None:
            raise SOL_Error(4408, "No API Key was setup")
        if len(self.commands) == 0:
            raise SOL_Error(4408, "No commands were set up")
        # start up the compression of any files present
        for fo in self._file_list:  # type: SOL_File
            fo.compress_and_hash()

    def dict(self) -> dict:
        # Form the package
        return{"commands": self.commands}