
GPPPARAMS := -std=c++23 -Wall -Wextra -Wpedantic


client: main.cpp argparse.o protocol.o
	g++ $(GPPPARAMS) $^ -o client

repl.o: repl.cpp repl.cpp
	g++ $(GPPPARAMS) -c repl.cpp

argparse.o: argparse.hpp argparse.cpp
	g++ $(GPPPARAMS) -c argparse.cpp

protocol.o: protocol.hpp protocol.cpp
	g++ $(GPPPARAMS) -c protocol.cpp


clean:
	rm -f client *.o

