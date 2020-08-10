CXXSOURCES		= main.cpp
CXXFLAGS		= -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS			= -pthread
DIRS			= static/upload

debug: $(DIRS)
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -g -fsanitize=address,undefined

analyze: $(DIRS)
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -g -fsanitize=address,undefined -fanalyzer

release: $(DIRS)
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -O2

$(DIRS):
	mkdir -p $@

clean:
	rm -f logs/* static/upload/*
