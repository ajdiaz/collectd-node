COFFEE = coffee
OBJDIR = lib
SRC    = src/collectd.coffee

all: $(OBJDIR)/collectd.js

%.js: $(SRC)
	$(COFFEE) -o $(OBJDIR) $<

clean:
	rm -f $(OBJDIR)/collectd.js
