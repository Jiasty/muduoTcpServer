all:tcpServer tcpClient
tcpServer:tcpServer.cpp
	g++ -std=c++11 $^ -o $@
tcpClient:tcpClient.cpp
	g++ -std=c++11 $^ -o $@

.POHNY:clean
clean:
	rm -rf tcpServer tcpClient