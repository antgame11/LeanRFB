CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -g -std=c99 -Iinclude
LDFLAGS = -L. -lleanrfb -ljpeg -lcrypto
X11_LDFLAGS = -lX11 -lXext -lXtst -lXfixes

LIB_OBJS = src/leanrfb.o src/leanrfb_hextile.o src/leanrfb_jpeg.o
LIB_NAME = libleanrfb.a

all: $(LIB_NAME) demo_server x11_vnc_server

$(LIB_NAME): $(LIB_OBJS)
	ar rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

demo_server: examples/demo_server.o $(LIB_NAME)
	$(CC) -o $@ examples/demo_server.o $(LDFLAGS)

examples/demo_server.o: examples/demo_server.c
	$(CC) $(CFLAGS) -c -o $@ $<

x11_vnc_server: examples/x11_vnc_server.o $(LIB_NAME)
	$(CC) -o $@ examples/x11_vnc_server.o $(LDFLAGS) $(X11_LDFLAGS)

examples/x11_vnc_server.o: examples/x11_vnc_server.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o examples/*.o $(LIB_NAME) demo_server x11_vnc_server

.PHONY: all clean
