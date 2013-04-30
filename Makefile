LEX=flex
CFLAGS=-I. -g
PKGCONFIG=pkg-config
GLIBFLAGS_COMPILE=`$(PKGCONFIG) --cflags glib-2.0`
GLIBFLAGS_LINK=`$(PKGCONFIG) --libs glib-2.0`

tcpdumpMapper: tcpdumpMapper_scanner.o tcpdumpMapper.o
	$(CC) -o $@ $(LDFLAGS) $(GLIBFLAGS_LINK) $^

tcpdumpMapper.o: tcpdumpMapper.c tcpdumpMapper.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GLIBFLAGS_COMPILE) -o $@ -c tcpdumpMapper.c 
	
tcpdumpMapper_scanner.o: tcpdumpMapper_scanner.c tcpdumpMapper.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GLIBFLAGS_COMPILE) -o $@ -c tcpdumpMapper_scanner.c

tcpdumpMapper_scanner.c: tcpdumpMapper_scanner.l
	$(LEX) $(LFLAGS) -o $@ $^
clean:
	$(RM) *.o *.*~ tcpdumpMapper_scanner.c tcpdumpMapper
