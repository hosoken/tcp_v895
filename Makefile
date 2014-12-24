CXX        = g++
RM         = rm -f
CXXFLAGS   = -O2 -Wall

FLAGS      = $(CXXFLAGS)
LIBS       = 

v895: v895.o
	@echo Linking $@ ...
	@$(CXX) -o $@ $^ $(LIBS)

clean:
	@echo Cleaning up ...
	@$(RM) *.o *~
	@$(RM) v895

%.o: %.cc
	@echo Compiling $< ...
	@$(CXX) $(FLAGS) -c $< -o $@
