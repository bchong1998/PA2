# PA2

This PA2 is done by:
Brandon Chong (1004104)
Glen Chen Jie (1004095)

It comprises of two protocols: CP1 with SP2 and CP2 with SP2

To compile the CP1, CP2, SP1 and SP2, run:
``` javac CP1.java ```
``` javac CP2.java ```
``` javac SP1.java ```
``` javac SP2.java ```

To run the first Confidentiality Protocol, first open two terminals and direct to PA2.
In the first terminal inside PA2's directory, run:
``` java SP1 ```
This starts the server.

In the second terminal, run:
``` java CP1 <filename> ```
<filename> is the file you want to send to the server.

You can send multiple files, separated by a space, for example:
``` java CP1 100.txt 1000.txt 10000.txt ```

To run the seconnd Confidentiality Protocol, first open two terminals and direct to PA2.
In the first terminal inside PA2's directory, run:
``` java SP2 ```
This starts the server.

In the second terminal, run:
``` java CP2 <filename> ```

You can send multiple files, separated by a space, for example:
``` java CP2 100.txt 1000.txt 10000.txt ```

The first terminal will display the authentication process and whether the file has been received.