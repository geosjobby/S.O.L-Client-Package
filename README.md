# - S.O.L Client Connector Package - v0.3.0

This is the standardized connector between any client application and the SOL API.
The primary reason this package was assembled is that there are various client applications which all need the SOL API to work properly.
They all have to connect to it in a similar way or their connection will be refused by the API.

---
## Details and features
- End-to-end encryption with the API Server
- Base error handling, but does not do anything with the API return codes.
The client application is meant to handle the different error codes on a use case basis.
- Large and small File transmission by use of compression, download and upload.
- Variable compression depth for each file object.

---

## Usage
The code below is an example of how the connection and package classes might be setup to work correctly:
```python
from SOL_Client_Connector import (
	SOL_Connector,	# Connector class
	SOL_Package, 	# Package class to assemble the commands in
	SOL_Error,	# Error Exception object
        SOL_File        # File Object which only reads the file on send of the whole package 
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
        api_key=...,  			# String Input of your API key
        credentials={
            "username": ...,	# String Input
            "password": ...		# String Input
        }  
    )  

# *-*
# Populate the Package Object
# *-*
    package.command_add(                    # Example commands, NOT USABLE COMMANDS
        {"ping": None},		            # Allowed chaining of multiple commands after each other.
        {"file": SOL_File(filepath="...")}, # Custom SOl_File object to correctly insert files into a command.
                                            # This file will only be read and decoded to transmittable bytes
                                            #   on the actual sending of the package.
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
## Version notes: 
### v0.2.0 - 2022.01.27
- Mayor rewrite of the entire conversation flow between the client and the API.
- Compression of a file is now handled in chunks and is technically (not implemented) possible to change the size of this chunk
- Larger file sizes (5+GB) are now supported, though the true limit has not been tested.
- Encryption class was removed and replaced by standalone functions.

---

Made By Andreas Sas, 2022