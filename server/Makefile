
GPPPARAMS := -std=c++23 -Wall -Wextra -Wpedantic


client: main.cpp protocol.o
	g++ $(GPPPARAMS) $^ -o server

protocol.o: protocol.hpp protocol.cpp
	g++ $(GPPPARAMS) -c protocol.cpp


clean:
	rm -rf server *.o storage

