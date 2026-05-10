CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Isrc
OBJDIR = obj

main: src/main.cc src/engine.cc src/parse_syscall.cc | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -o $(OBJDIR)/main $^

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -f $(OBJDIR)/*

.PHONY: main clean
