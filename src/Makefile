CC = apxs
CFLAGS = -i -a -Wc,-std=gnu99 -c 
LDFLAGS = `pkg-config --cflags --libs jansson openssl libcurl` 
DBG_CFLAGS = -g -DDEBUG 

SOURCES = mod_perimeterx.c curl_pool.c px_cookie.c
#SOURCES = mod_perimeterx.c curl_pool.c px_cookie.c px_json.c 
HEADERS =  px_types.h curl_pool.h px_cookie.h
#HEADERS =  curl_pool.h px_types.h px_json.h px_cookie.h

all: clean mod

mod: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES)

debug: $(HEADERS) $(SOURCES);
	$(CC) $(CFLAGS) $(DBG_CFLAGS) $(LDFLAGS) $(SOURCES)

clean:
	rm -f *.{lo,slo,la,o}
