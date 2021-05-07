# WebsocketCommunication
Client, proxy, and server programs to communicate through websockets. More detailed explanation on the project can be found in the file README2.txt, this includes running instructions, errors, examples, etc.

## Examples
Upon initiation of the server and 5 proxies, the user is given these messages which indicate working functionality:

Server:
![](https://github.com/tsunamiyama/WebsocketCommunication/blob/main/examplePictures/serverpicone.png)

Proxies:
![](https://github.com/tsunamiyama/WebsocketCommunication/blob/main/examplePictures/proxypicone.png)

After the server and proxies are correctly initiated, the client program can be run. This program will connect to a random proxy of the 5 open and ask it a question. The proxy will then check its local cache file to see if it has already been asked this question. If it has, it returns the same answer which is stored, if not, it will forward the question to the server and store the answer before returning it to the client.

![](https://github.com/tsunamiyama/WebsocketCommunication/blob/main/examplePictures/clientPicOne.png)
