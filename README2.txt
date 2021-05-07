CS165 Project 2 Submission by Kris Tsuchiyama SID: 862043811

In order to compile and run the included code, follow these instructions (this is a modified version of the original TCPSocket_iii):

(After downloading and extracting the code)
$ cd TCPSocket_iii
$ source scripts/setup.sh
$ cd certificates
$ make

The server, proxy, and client can be run in this order from the TCPSocket_iii directory. Before running these commands read the notes below:

server:
$ ./build/src/server 9999

proxy:
$ ./build/src/proxy *portnumber*

client:
$ ./build/src/client 127.0.0.1

For the proxy, my code is designed to work with 5 proxies, with port numbers 9994, 9995, 9996, 9997, 9998. Run the code to start the proxy in 5 different windows with one using each port.

The included server, proxy, and client access various included files. The paths of these files are included, but will need to be edited to the correct path depending on where you downloaded the files.
Some places to change the file paths:
- functions, many of which are used to read/write to files
- TLS certificate set up

After changing the file paths, run make in the build directory and use the corresponding commands to run the server, proxy, and client when back in the TCPSocket_iii directory.

SERVER:
The server is largely the same as the given starter code. The main differences are the TLS set up, and the ability for the server to read the included file to find correct outputs based on what the client sent.

PROXY:
The proxy runs and uses fork() to handle multiple client connections. The proxy will not try to connect to the server unless it has connected to a client and recieved a request which it does not already have the answer for.
It has a bloomfilter with a hardcoded size determined to provide <1% false positives assuming the blacklist has 30000 objects. The blacklist can be edited by adding/removing from the "blacklist.txt" file included in
the src proxy folder. The bloomfilter uses 5 hash functions, all of which are from the provided Murmur3 hash functions. The proxy also had an included localcache file. It will add unseen requested objects and the respective answer to this file and use it find answers to duplicate questions. There is only one localcache file,
so the 5 proxies will all share it. This can be easily changed by editing the proxy functions to pick the localcache file based on its port number, but due to time issues was not changed in this submission. If the requested
objected by the client is not in the bloomfilter or localcache, then the proxy will connect to the server and request the given object and then return it to the client and disconnect. After running the proxies, make sure
to delete the contents of the localcache file, otherwise the next time it is run, the local cache with include the old submissions and not have to contact the server. Additions to the blacklist.txt should not affect
the proxy unless it totals more than 30000 total objects, since this will push the false positive rate above 1%.

CLIENT:
The client is largely the same as the given starter code. It will randomly choose an object to request from the provided "input.txt" file and use rendezvous hashing to decide which port to connect to and so the right proxy.
The rendezvous hashing is done using the included Murmur3 hash. Since the port number is being chosen by the rendezvous hashing, there is no need to include it when running the code, just the ip address which is local in this case. 
After recieving the given object the connection is closed.


The server, proxy, and client all print to the terminal details about each step which they successfully complete as well as error messages based on what went wrong, if anything.


ISSUES:
There should be no compiling/running issues with my code when using the correct file paths. The proxy localcache was meant to be implemented using malloc and therefore not needing to have extra files. However, I
implemented the proxy server using fork() to handle multiple client requests. This works correctly, but does not allow me to edit a malloc() space because the changes to the variables in a fork do not carry over to
the original variables. Due to time, I was not able to switch my implementation to multithreading, which would solve this issue. 

EXAMPLES:
The links below are examples of how the given code should look when run:
SERVER: https://prnt.sc/w044ou
PROXY: https://prnt.sc/w0457w
CLIENT: https://prnt.sc/w045dc

