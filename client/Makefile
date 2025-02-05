
GPPPARAMS := -std=c++23 -Wall -Wextra -Wpedantic -I ../monocypher-cpp/include/ -lbsd -lsockpp


client: main.cpp argparse.o protocol.o Monocypher.o keystore.o
	g++ $(GPPPARAMS) $^ -o client

repl.o: repl.cpp repl.cpp
	g++ $(GPPPARAMS) -c repl.cpp

argparse.o: argparse.hpp argparse.cpp
	g++ $(GPPPARAMS) -c argparse.cpp

protocol.o: protocol.hpp protocol.cpp
	g++ $(GPPPARAMS) -c protocol.cpp

keystore.o: keystore.hpp keystore.cpp
	g++ $(GPPPARAMS) -c keystore.cpp

Monocypher.o: ../monocypher-cpp/src/Monocypher.cc
	g++ $(GPPPARAMS) -c $^


clean:
	rm -f client *.o

