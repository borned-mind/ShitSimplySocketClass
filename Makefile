NAMELIBRARY=simplysocket
FLAGS = -fPIC
TESTPROGRAMNAME=testprogram
exit_library:=

ifeq ($(uname_S), Windows)
    exit_library+=library/lib$(NAMELIBRARY).dll
else 
    exit_library+=library/lib$(NAMELIBRARY).so
endif


all: socket.o somefunc.o library SimplyClassCopyHeaders

SimplyClassCopyHeaders:
	cp source/socket.hpp library/
	cp source/somefunc.hpp library/
	cp source/sockets_stuff.hpp library/
test:
	g++ source/main.cpp -L library/ -l$(NAMELIBRARY) -o $(TESTPROGRAMNAME)

socket.o:
	g++ -c $(FLAGS) source/socket.cpp -o build/socket.o
somefunc.o:
	g++ -c $(FLAGS) source/somefunc.cpp -o build/somefunc.o
	
library:
	mkdir library
	g++ -shared build/*.o -o $(exit_library)
clean:
	rm -rf library
	rm -rf $(TESTPROGRAMNAME)
	rm -rf build/*
reagain: clean all test
	
starttest: reagain
	LD_LIBRARY_PATH=./library ./$(TESTPROGRAMNAME)
