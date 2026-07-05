CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -g -std=c99 -Iinclude
LDFLAGS = -L. -lleanrfb -ljpeg -lcrypto -lx264
X11_LDFLAGS = -lX11 -lXext -lXtst -lXfixes
CLIENT_LDFLAGS = -lavcodec -lswscale -lavutil -lX11 -lcrypto

LIB_OBJS = src/leanrfb.o src/leanrfb_hextile.o src/leanrfb_jpeg.o src/leanrfb_h264.o
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

x11_vnc/x11_vnc_server.o: x11_vnc/x11_vnc_server.c
	$(CC) $(CFLAGS) -c -o $@ $<

vncviewer: vncview/vncview.o
	$(CC) -o $@ vncview/vncview.o $(CLIENT_LDFLAGS)

vncview/vncview.o: vncview/vncview.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o examples/*.o x11_vnc/*.o vncview/*.o $(LIB_NAME) demo_server x11_vnc_server vncviewer

.PHONY: all clean
