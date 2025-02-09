
GPPPARAMS := -std=c++23 -Wall -Wextra -Wpedantic -I ../monocypher-cpp/include/ -lbsd -lsockpp -g

client: main.cpp protocol.o server.o Monocypher.o
	g++ $(GPPPARAMS) $^ -o server

protocol.o: protocol.hpp protocol.cpp
	g++ $(GPPPARAMS) -c protocol.cpp

server.o: server.hpp server.cpp
	g++ $(GPPPARAMS) -c server.cpp

Monocypher.o: ../monocypher-cpp/src/Monocypher.cc
	g++ $(GPPPARAMS) -c $^

clean:
	rm -rf server *.o storage

