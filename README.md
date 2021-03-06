Capture The Flag
===========

There is two ways for players to submit flags: using the python script found or via the UI (Not created yet). Flags can 
created via the `createFlag.py` script which will allow for naming and applying points. Flags can be made 'venomous' by 
the script maker. Just like in real life, players should not be running any script he/she comes across. This will should 
make the CTF a bit more interesting by requiring a bit of code review before executing. Executing venomous flags result 
in a punishment (loss of points) which will be applied to players that execute a the script.

The `ctfCollectory.py` must be running to listen for flags. Users will only be allowed to submit a flag once. The user
must also have an account. User accounts can be created with `creatUser.py`.

Server keys are located in the keys directory. These keys are used to ensure sniffing of traffic doesn't give up unique 
flag identifiers or passwords. They are created upon running `setup.py`. The setup script will also setup the database 
with appropriate tables for tracking of flags and users password, salt, points, messages, and submitted flags. The 
`setup.py` script must be ran first.

This is my first pass at creating a unique, potentially more challenging, Capture The Flag. Please feel free to submit
some idea's that are inline with the current theme of this CTF framework.
 
Requirements
=====

* m2crypto

Usage
=====

### Setup.py
Setup needs to be ran first. This script creates the database, sets up the tables, and checks if required modules are installed.

Simply run:
```python setup.py```

### ctfCollector.py
CTFCollector is the listener. This script listens on designated port for incoming connections from flag entries. This
 script will also update the tables as flag entries come in. Currently set to accept 10 threads.

Simply run:
```python ctfCollector.py```

### createFlag.py
This script will create the flag. The flag can be a script or just a UUID. Flag creators must provide a name and number 
of points for each flag. Flag creators have the option to make the flag venomous. A venomous flag will remove points 
from the user if executed.

Required:
```python createFlag.py -n NAMEOFFLAG -p NUMBER```

Usage:
```
usage: createFlag.py [-h] -n NAME -p POINTS [-v VENOMOUS] [-u]

Used to create flags

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Enter name for flag
  -p POINTS, --points POINTS
                        Enter how many points flag is worth
  -v VENOMOUS, --venomous VENOMOUS
                        Enter if flag is venomous (1), or not (0)
  -u, --justuuid        Enter to create just a uuid and no script
```

### createUser.py
This script will create a user.

Required:
```python createUser.py -u USERNAME -p PASSWORD```

Usage:

```
Used to create user

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  Enter username
  -p PASSWORD, --password PASSWORD
                        Enter password
```

ToDo's
=====

### createUser.py
* ~~ToDo: Logic to make sure user doesn't already exist~~
* ~~ToDo: Insert hashed password into user database~~
* ~~ToDo: Insert salt into salt database~~

### ctfCollector.py
* ToDo: Find a way to give feedback to submitter of the flag
* ~~ToDo: pull salt from salt database~~
* ~~ToDo: pull hashed password from user database~~
* ~~ToDo: Interact with user_messages table - update with new messages by users~~
* ~~ToDo: Interact with user_points table - Logic to update scoring in user database~~
* ~~ToDo: Interact with user_flags table - Update flags as user sends them~~
* ~~ToDo: Interact with flags table - Check if flag is venomous and deduct set number of points~~
* ~~ToDo: Create logic for user to submit flag only once~~ (Should be completed check_if_user_exists function)
* ~~ToDo: Create function to validate flag exists~~ (Should be completed check_if_uuid_exists function)
* ~~ToDo: Create function to validate user exists~~ (Should be completed check_if_usrflag_exists function)

### createFlag.py
* ToDo: Give option for creating Windows Executable flag
* ~~ToDo: Add randomized encoded function for 'Poisoned Flags'~~
* ~~ToDo: Fix venomous flag to just require to be added, no argument required~~
* ~~ToDo: Add option to include ctfCollector IP address~~
* ~~ToDo: Check if uuid exists, if exists create new uuid automatically~~ (Should be completed with check_if_uuid_exists)
* ~~ToDo: Check if name exists, if exists ask user for new name~~ (Should be completed with check_if_flagname_exists)
* ~~ToDo: Add option to create just UUID~~
* ~~ToDo: Give option for venomous flag~~
* ~~ToDo: Update flag database when creating flag/UUID~~
* ~~ToDo: Add option to add points to UUID created~~
* ~~ToDo: Add option to name flag~~

### Setup.py
* ~~ToDo: Create user/salt database~~
* ~~ToDo: Setup flag database~~
* ~~ToDo: Setup user database for login/tracking of points (current version only tracks name/points/flags~~
* ~~ToDo: Change prints to logging - Include setup.log~~
* ~~ToDo: Check for crypto package installation, make recommendations~~

### All
* ToDo: Clean/Optimize script
* ToDo: Create front-end for interacting with scripts, tracking of player scores, and adding UUIDs.
* ~~ToDo: When user is created, update user_points table with 0 points~~
* ~~ToDo: Ensure adequate comments~~
* ~~ToDo: Add more exception handling~~

Needs plenty of work. If you have more idea's please submit. 