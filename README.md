# - S.O.L Client Connector Package - v0.1.4

This is the standardized connector between any client application and the SOL API.
The primary reason this package was assembled is that there are various client applications which all need the SOL API to work properly and have to connect to it in a similar way or their connection will be refused by the API.

---
## Details and features
- End-to-end encryption with the API Server
- Base error handling, but does not do anything with the API return codes.
The client application is meant to handle the different error codes on a use case basis.


---
## Usage
The code below is an example of how the connection and package classes might be setup to work correctly:
```python
from SOL_Client_Connector import (
	SOL_Connector,	# Connector class
	SOL_Package, 	# Package class to assemble the commands in
	SOL_Error	# Error Exception object
)

# *-*
# Set up the connection. 
# This does not create a permanent connection!
# *-*
try: 
    Connection = SOL_Connector()  
    Connection.connection_setup(  
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
    package.command_add(
        {"ping": None},		# Example
        {"ping": None},		# Chain multiple commands after each other 
    ) 			        # to insert multiple commands.

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

Pip install by: 
```
pip install SOL-Client-Connector-Package
``` 

---
Made By Andreas Sas, 2022