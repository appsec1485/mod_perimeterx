CC = apxs
CFLAGS = -g

all: clean mod

mod: mod_perimeterx.c
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` mod_perimeterx.c

b: b.c
	gcc b.c -std=gnu99 -ljansson -ob

clean:
	rm -f *.{lo,slo,la,o} b
