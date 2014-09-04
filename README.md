Capture The Flag
===========

There will be two ways for players to submit flags to the score tracker: using the python script found or via the UI. 
Flags can created via the `createFlag.py` script which will allow for naming and applying points. Just like in real 
life, players should not be running any script he/she comes across. Some scripts will be 'venomous' to make the CTF 
more interesting. Punishment (loss of points) will be applied to players that execute a destructive script.

This is my first pass at creating a unique, potentially more challenging, Capture The Flag. Please feel free to submit
some idea's that are inline with the current theme of this CTF framework.
 
Requirements
=====

* m2crypto
* pycrypto

ToDo's
=====

### ctfCollector.py
* ToDo: UUID/Flag scoring database
* ToDo: Logic to update scoring in user database
* ToDo: Create logic for user to submit flag only once

### createFlag.py
* ToDo: Give option for venomous flag
* ToDo: Update flag database when creating flag/UUID
* ToDo: Add randomized encoded function for 'Poisoned Flags'
* ToDo: Add option to add points to UUID created
* ToDo: Add option to name flag
* ToDo: Add option to create just UUID

### Setup.py
* ~~ToDo: Setup flag database~~
* ~~ToDo: Setup user database for login/tracking of points (current version only tracks name/points/flags~~
* ~~ToDo: Change prints to logging - Include setup.log~~
* ~~ToDo: Check for crypto package installation, make recommendations~~

### All
* ToDo: Clean/Optimize script
* ToDo: Create front-end for interacting with scripts and tracking of player scores.

Needs plenty of work. If you have more idea's please submit. 