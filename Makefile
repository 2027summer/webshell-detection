CXX = clang++
DETECTION_REQUIRE_LISTEN ?= 1
DETECTION_DEBUG ?= 0
CXXFLAGS = -std=c++20 -Wall -Isrc -DDETECTION_REQUIRE_LISTEN=$(DETECTION_REQUIRE_LISTEN) -DDETECTION_DEBUG=$(DETECTION_DEBUG)
OBJDIR = obj

main: src/main.cc src/engine.cc src/parse_syscall.cc | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -o $(OBJDIR)/main $^

test: tests/parse_syscall_arg_test.cc src/parse_syscall.cc | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -o $(OBJDIR)/parse_syscall_arg_test $^
	$(OBJDIR)/parse_syscall_arg_test

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -f $(OBJDIR)/*

.PHONY: main test clean
