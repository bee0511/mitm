CXX = g++
CXXFLAGS = -std=c++17
LDFLAGS = -lpthread -lnetfilter_queue
SRCDIR = src
OBJDIR = obj
BINDIR = .

TARGETS = mitm_attack pharm_attack
COMMON_OBJS = local.o arp.o
OBJECTS = $(addprefix $(OBJDIR)/, $(addsuffix .o, $(TARGETS)) $(COMMON_OBJS))

all: $(OBJDIR) $(TARGETS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

mitm_attack: $(OBJDIR)/mitm_attack.o $(addprefix $(OBJDIR)/, $(COMMON_OBJS))
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $(BINDIR)/$@

pharm_attack: $(OBJDIR)/pharm_attack.o $(addprefix $(OBJDIR)/, $(COMMON_OBJS))
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $(BINDIR)/$@

clean:
	rm -rf $(OBJECTS) $(addprefix $(BINDIR)/, $(TARGETS)) $(OBJDIR)