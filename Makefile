CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -g -std=c99 -Iinclude -D_REENTRANT
LDFLAGS = -L. -lleanrfb -ljpeg -lcrypto -lx264 -lvpx -lavcodec -lavutil -lpulse-simple -lpulse -lpthread
X11_LDFLAGS = -lX11 -lXext -lXtst -lXfixes -lXrandr
CLIENT_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
CLIENT_LDFLAGS = $(shell pkg-config --libs gtk+-3.0) -lavcodec -lswscale -lavutil -ljpeg -lcrypto -lpulse-simple -lpulse -lpthread
WAYLAND_CFLAGS = $(shell pkg-config --cflags gio-2.0 libpipewire-0.3)
WAYLAND_LDFLAGS = $(shell pkg-config --libs gio-2.0 libpipewire-0.3)

# Non-essential vncviewer diagnostic logging (connection lifecycle, encoding negotiation,
# UDP transport handshake/reassembly, decoder state) is compiled out by default. Build
# with `make clean && make vncviewer DEBUG=1` to enable it on stderr — object files
# aren't tracked per-flag, so a clean rebuild is needed when toggling this.
ifdef DEBUG
CLIENT_CFLAGS += -DVNC_DEBUG
endif

LIB_OBJS = src/leanrfb.o src/leanrfb_hextile.o src/leanrfb_jpeg.o src/leanrfb_h264.o src/leanrfb_vp9.o src/leanrfb_udp.o src/leanrfb_audio.o
LIB_NAME = libleanrfb.a

all: $(LIB_NAME) demo_server x11_vnc_server wayland_vnc_server vncviewer

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

wayland_vnc_server: wayland_vnc/wayland_vnc_server.o $(LIB_NAME)
	$(CC) -o $@ wayland_vnc/wayland_vnc_server.o $(LDFLAGS) $(WAYLAND_LDFLAGS)

wayland_vnc/wayland_vnc_server.o: wayland_vnc/wayland_vnc_server.c
	$(CC) $(CFLAGS) $(WAYLAND_CFLAGS) -c -o $@ $<

vncviewer: vncview/vncview.o vncview/vnc_client_core.o
	$(CC) -o $@ vncview/vncview.o vncview/vnc_client_core.o $(CLIENT_LDFLAGS)

vncview/vncview.o: vncview/vncview.c
	$(CC) $(CFLAGS) $(CLIENT_CFLAGS) -c -o $@ $<

vncview/vnc_client_core.o: vncview/vnc_client_core.c
	$(CC) $(CFLAGS) $(CLIENT_CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o examples/*.o x11_vnc/*.o vncview/*.o wayland_vnc/*.o $(LIB_NAME) demo_server x11_vnc_server wayland_vnc_server vncviewer x11_vnc_server.conf vncview_web.js vncview_web.wasm vncview_web.html

wasm: vncview/vncview_web.c vncview/vnc_client_core.c
	emcc -O3 -Wall -Wextra -std=gnu99 vncview/vncview_web.c vncview/vnc_client_core.c -o vncview_web.js \
		-sUSE_SDL=2 -sUSE_LIBJPEG=1 -sALLOW_MEMORY_GROWTH=1 -sEXPORTED_RUNTIME_METHODS=ccall,cwrap \
		-lwebsocket.js
	cp -f vncview/vncview_web.html .

.PHONY: all clean wasm
