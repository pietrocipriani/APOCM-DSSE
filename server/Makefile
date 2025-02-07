
GPPPARAMS := -std=c++23 -Wall -Wextra -Wpedantic -I ../monocypher-cpp/include/ -lbsd 


client: main.cpp protocol.o Monocypher.o
	g++ $(GPPPARAMS) $^ -o server

protocol.o: protocol.hpp protocol.cpp
	g++ $(GPPPARAMS) -c protocol.cpp

Monocypher.o: ../monocypher-cpp/src/Monocypher.cc
	g++ $(GPPPARAMS) -c $^

clean:
	rm -rf server *.o storage

