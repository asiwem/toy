CXXSOURCES		= main.cpp
CXXFLAGS		= -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS			= -pthread

debug:
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -g -fsanitize=address,undefined

analyze:
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -g -fsanitize=address,undefined -fanalyzer

release:
	$(CXX) $(CXXSOURCES) -o bin $(CXXFLAGS) $(LDFLAGS) -O2

clean:
	rm -f logs/* static/upload/*
