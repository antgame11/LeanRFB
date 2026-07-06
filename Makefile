CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -g -std=c99 -Iinclude
LDFLAGS = -L. -lleanrfb -ljpeg -lcrypto -lx264 -lvpx -lavcodec -lavutil
X11_LDFLAGS = -lX11 -lXext -lXtst -lXfixes
CLIENT_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
CLIENT_LDFLAGS = $(shell pkg-config --libs gtk+-3.0) -lavcodec -lswscale -lavutil -ljpeg -lcrypto -lpthread

LIB_OBJS = src/leanrfb.o src/leanrfb_hextile.o src/leanrfb_jpeg.o src/leanrfb_h264.o src/leanrfb_vp9.o src/leanrfb_udp.o
LIB_NAME = libleanrfb.a

all: $(LIB_NAME) demo_server x11_vnc_server vncviewer

$(LIB_NAME): $(LIB_OBJS)
	ar rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

demo_server: examples/demo_server.o $(LIB_NAME)
	$(CC) -o $@ examples/demo_server.o $(LDFLAGS)

examples/demo_server.o: examples/demo_server.c
	$(CC) $(CFLAGS) -c -o $@ $<

x11_vnc_server: x11_vnc/x11_vnc_server.o $(LIB_NAME)
	$(CC) -o $@ x11_vnc/x11_vnc_server.o $(LDFLAGS) $(X11_LDFLAGS)
	cp -f x11_vnc/x11_vnc_server.conf .

x11_vnc/x11_vnc_server.o: x11_vnc/x11_vnc_server.c
	$(CC) $(CFLAGS) -c -o $@ $<

vncviewer: vncview/vncview.o
	$(CC) -o $@ vncview/vncview.o $(CLIENT_LDFLAGS)

vncview/vncview.o: vncview/vncview.c
	$(CC) $(CFLAGS) $(CLIENT_CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o examples/*.o x11_vnc/*.o vncview/*.o $(LIB_NAME) demo_server x11_vnc_server vncviewer x11_vnc_server.conf

.PHONY: all clean
