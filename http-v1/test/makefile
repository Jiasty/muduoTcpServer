all:server client
server:server.cpp
	g++ -std=c++11 $^ -o $@
client:tcpClient.cpp
	g++ -std=c++11 $^ -o $@

.POHNY:clean
clean:
	rm -rf server client