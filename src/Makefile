CC = apxs
CFLAGS = -i -a -Wc,-std=gnu99 -c
LDFLAGS = `pkg-config --cflags --libs jansson openssl libcurl`

SOURCES = mod_perimeterx.c curl_pool.c px_cookie.c px_json.c px_utils.c px_enforcer.c
HEADERS =  px_types.h curl_pool.h px_cookie.h px_json.h px_utils.h px_enforcer.h

all: clean mod

mod: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES)

debug: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DDEBUG $(LDFLAGS) $(SOURCES)

#docker:

#test:

clean:
	rm -f *.{lo,slo,la,o}
