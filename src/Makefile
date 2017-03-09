CC = apxs
CFLAGS = -i -a -Wc,-std=gnu99 -c 
LDFLAGS = `pkg-config --cflags --libs jansson openssl libcurl` 
DBG_CFLAGS = -g -DDEBUG 

SOURCES = mod_perimeterx.c curl_pool.c
HEADERS =  curl_pool.h


all: clean mod

mod: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES)

debug: $(HEADERS) $(SOURCES);
	$(CC) $(CFLAGS) $(DBG_CFLAGS) $(LDFLAGS) $(SOURCES)

clean:
	rm -f *.{lo,slo,la,o}
