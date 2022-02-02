# - S.O.L Client Connector Package - v0.3.3

This is the standardized connector between any client application and the SOL API.
The primary reason this package was assembled is that there are various client applications which all need the SOL API to work properly.
They all have to connect to it in a similar way or their connection will be refused by the API.

---
## Details and features
- End-to-end encryption with the API Server
- Base error handling, but does not do anything with the API return codes.
The client application is meant to handle the different error codes on a case by case basis.
- Large and small File download and upload, by use of compression. The compression level can be set by the client on upload.
- Variable compression depth for each file object.
- Retrieve error data from the Server

---

## Usage
The code below is an example of how the connection and package classes might be setup to work correctly:
```python
from SOL_Client_Connector import (
	SOL_Connector,	# Connector class
	SOL_Package, 	# Package class to assemble the commands in
	SOL_Error,	# Error Exception object
        SOL_File,        # File Object which only reads the file on send of the whole package 
        SOL_Credentials
)

# *-*
# Set up the connection. 
# This does not create a permanent connection!
# *-*
try: 
    Connection = SOL_Connector( 
        address=...,	# String Input  
        port=...  	# Integer Input
    )

# *-*
# Create the Package Object
# *-*
    package = SOL_Package(  
        api_key=...  			# String Input of your API key
    )  
    
# *-*
# Create the credentials object
# *-* 
    cred = SOL_Credentials(     # Best to set these in the os keyring to track long term.
            username="...",     
            password="...",     
            password_new="..."  # Is not needed by default, only for password change commands
        )

# *-*
# Populate the Package Object
# *-*
    package.command_add(                    # Example commands, NOT USABLE COMMANDS
        {"ping": None},		            # Allowed chaining of multiple commands after each other.
        {"file": SOL_File(                  # Custom SOl_File object to correctly insert files into a command.
            filepath=str,                   # This file will only be read and decoded to transmittable bytes
            compression=int                 #   on the actual sending of the package.
        )}, 
        {"change_password": cred},          # Always use the same cred object, and do not create a new object 
        {"password_needed": cred}           #   Only one set of credentials is allowed per conversation
    )
    
# *-*
# Send the Package and wait for the result
# Blocking Action!
# *-*
    result = Connection.send(  
        package  
    )

# *-*
# Error handling
# *-*
except SOL_Error as e:
    print(e)

```

---
## Links
Project files can be found at:
- [GitHub Repo](https://github.com/DirectiveAthena/S.O.L-Client-Package) 
- [Pypi link](https://pypi.org/project/SOL-Client-Connector-Package/)

Pip installs by the following command: 
```
pip install SOL-Client-Connector-Package
```

---

Made By Andreas Sas, 2022