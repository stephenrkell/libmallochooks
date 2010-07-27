CXXFLAGS += -I../include
CXXFLAGS += -std=gnu++0x -g3 

LDFLAGS += -L../src -Wl,-R$(realpath ../src) 

LDLIBS  += -lprocessimage
LDLIBS  += -ldwarfpp
LDLIBS  += -lc++fileno 
LDLIBS  += -lsrk31c++
LDLIBS  += -ldwarf 
LDLIBS  += -lelf -lsupc++ -liberty -lboost_regex
LDLIBS  += -lunwind -lunwind-ptrace -lunwind-x86 
LDLIBS  += -ldl

SRC := $(wildcard *.cpp)
ALL_TESTS := $(patsubst %.cpp,%,$(SRC))

default: $(ALL_TESTS)

DEPS := $(patsubst %.cpp,.%.cpp.d,$(SRC))

$(DEPS): .%.cpp.d: %.cpp
	g++ -MM $(CXXFLAGS) "$<"  > "$@"

include $(DEPS)


