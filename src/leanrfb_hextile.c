#include "leanrfb_internal.h"
#include <string.h>

// Temporary buffer for encoding a single tile (stack-allocated per call)

typedef struct {
    uint8_t x, y, w, h;
    uint32_t color;
} hextile_subrect_t;

int vnc_encode_hextile(vnc_client_t* client, const uint32_t* fb, int fb_width, int fb_height,
                       uint16_t rx, uint16_t ry, uint16_t rw, uint16_t rh) {
    (void)fb_height;
    uint8_t tile_buf[2048];  // Stack-allocated; safe since this is called single-threaded
    int bpp = get_pixel_size(&client->fmt, client->format_custom);
    uint32_t prev_bg = 0;
    uint32_t prev_fg = 0;
    int has_prev_bg = 0;
    int has_prev_fg = 0;
    
    for (uint16_t ty = ry; ty < ry + rh; ty += 16) {
        uint16_t th = (ry + rh - ty < 16) ? (ry + rh - ty) : 16;
        for (uint16_t tx = rx; tx < rx + rw; tx += 16) {
            uint16_t tw = (rx + rw - tx < 16) ? (rx + rw - tx) : 16;
            
            // Check write buffer space. Max size for one tile is tw*th*bpp + 32 bytes metadata.
            size_t max_tile_size = tw * th * bpp + 32;
            if (client_ensure_write_space(client, max_tile_size) < 0) {
                return -1;
            }
            
            // Analyze colors in the tile
            uint32_t colors[256];
            int color_counts[256];
            int num_colors = 0;
            
            for (int y = 0; y < th; y++) {
                const uint32_t* row_ptr = &fb[(ty + y) * fb_width + tx];
                for (int x = 0; x < tw; x++) {
                    uint32_t color = row_ptr[x];
                    int found = 0;
                    for (int i = 0; i < num_colors; i++) {
                        if (colors[i] == color) {
                            color_counts[i]++;
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        if (num_colors < 16) {
                            colors[num_colors] = color;
                            color_counts[num_colors] = 1;
                            num_colors++;
                        } else {
                            num_colors = 17; // Force Raw
                            break;
                        }
                    }
                }
                if (num_colors > 16) break;
            }
            
            uint8_t* p = tile_buf;
            
            if (num_colors > 16) {
                // Send Raw Tile (subencoding = 1)
                *p++ = 1;
                for (int y = 0; y < th; y++) {
                    const uint32_t* row_ptr = &fb[(ty + y) * fb_width + tx];
                    for (int x = 0; x < tw; x++) {
                        convert_pixel(row_ptr[x], p, &client->fmt);
                        p += bpp;
                    }
                }
            } else if (num_colors == 1) {
                // Solid Tile
                uint32_t bg = colors[0];
                if (has_prev_bg && bg == prev_bg) {
                    *p++ = 0; // Use previous background
                } else {
                    *p++ = 2; // BackgroundSpecified
                    convert_pixel(bg, p, &client->fmt);
                    p += bpp;
                    prev_bg = bg;
                    has_prev_bg = 1;
                }
            } else {
                // 2 to 16 colors: Use subrectangles
                // Background color is the most frequent color
                int bg_idx = 0;
                int max_count = 0;
                for (int i = 0; i < num_colors; i++) {
                    if (color_counts[i] > max_count) {
                        max_count = color_counts[i];
                        bg_idx = i;
                    }
                }
                uint32_t bg_color = colors[bg_idx];
                
                // Find all subrectangles for non-background pixels
                hextile_subrect_t subrects[256];
                int subrect_count = 0;
                
                for (int y = 0; y < th; y++) {
                    const uint32_t* row_ptr = &fb[(ty + y) * fb_width + tx];
                    int in_span = 0;
                    int span_start = 0;
                    uint32_t span_color = 0;
                    
                    for (int x = 0; x < tw; x++) {
                        uint32_t color = row_ptr[x];
                        if (color != bg_color) {
                            if (in_span) {
                                if (color == span_color) {
                                    // Continue same color span
                                } else {
                                    // End previous, start new
                                    subrects[subrect_count++] = (hextile_subrect_t){(uint8_t)span_start, (uint8_t)y, (uint8_t)(x - span_start), 1, span_color};
                                    span_start = x;
                                    span_color = color;
                                }
                            } else {
                                in_span = 1;
                                span_start = x;
                                span_color = color;
                            }
                        } else {
                            if (in_span) {
                                subrects[subrect_count++] = (hextile_subrect_t){(uint8_t)span_start, (uint8_t)y, (uint8_t)(x - span_start), 1, span_color};
                                in_span = 0;
                            }
                        }
                    }
                    if (in_span) {
                        subrects[subrect_count++] = (hextile_subrect_t){(uint8_t)span_start, (uint8_t)y, (uint8_t)(tw - span_start), 1, span_color};
                    }
                }
                
                // Merge spans vertically
                for (int i = 0; i < subrect_count; i++) {
                    if (subrects[i].h == 0) continue;
                    for (int j = i + 1; j < subrect_count; j++) {
                        if (subrects[j].h == 0) continue;
                        if (subrects[j].y == subrects[i].y + subrects[i].h &&
                            subrects[j].x == subrects[i].x &&
                            subrects[j].w == subrects[i].w &&
                            subrects[j].color == subrects[i].color) {
                            subrects[i].h += subrects[j].h;
                            subrects[j].h = 0;
                        }
                    }
                }
                
                int valid_subrects = 0;
                for (int i = 0; i < subrect_count; i++) {
                    if (subrects[i].h > 0) {
                        if (i != valid_subrects) {
                            subrects[valid_subrects] = subrects[i];
                        }
                        valid_subrects++;
                    }
                }
                
                uint8_t subencoding = 8; // AnySubrects
                if (!has_prev_bg || bg_color != prev_bg) {
                    subencoding |= 2; // BackgroundSpecified
                }
                
                int is_colored = (num_colors > 2);
                uint32_t fg_color = 0;
                if (!is_colored) {
                    // Only 1 foreground color
                    for (int i = 0; i < num_colors; i++) {
                        if (colors[i] != bg_color) {
                            fg_color = colors[i];
                            break;
                        }
                    }
                    if (!has_prev_fg || fg_color != prev_fg) {
                        subencoding |= 4; // ForegroundSpecified
                    }
                } else {
                    subencoding |= 16; // SubrectsColoured
                }
                
                // Estimate size
                size_t enc_size = 1; // subencoding
                if (subencoding & 2) enc_size += bpp;
                if (subencoding & 4) enc_size += bpp;
                enc_size += 1; // count
                enc_size += valid_subrects * (2 + (is_colored ? bpp : 0));
                
                if (enc_size >= (size_t)(tw * th * bpp) || valid_subrects > 24) {
                    // Fall back to Raw
                    *p++ = 1;
                    for (int y = 0; y < th; y++) {
                        const uint32_t* row_ptr = &fb[(ty + y) * fb_width + tx];
                        for (int x = 0; x < tw; x++) {
                            convert_pixel(row_ptr[x], p, &client->fmt);
                            p += bpp;
                        }
                    }
                } else {
                    // Write subrectangles
                    *p++ = subencoding;
                    if (subencoding & 2) {
                        convert_pixel(bg_color, p, &client->fmt);
                        p += bpp;
                        prev_bg = bg_color;
                        has_prev_bg = 1;
                    }
                    if (subencoding & 4) {
                        convert_pixel(fg_color, p, &client->fmt);
                        p += bpp;
                        prev_fg = fg_color;
                        has_prev_fg = 1;
                    }
                    *p++ = (uint8_t)valid_subrects;
                    for (int i = 0; i < valid_subrects; i++) {
                        if (is_colored) {
                            convert_pixel(subrects[i].color, p, &client->fmt);
                            p += bpp;
                        }
                        *p++ = (subrects[i].x << 4) | subrects[i].y;
                        *p++ = ((subrects[i].w - 1) << 4) | (subrects[i].h - 1);
                    }
                }
            }
            
            size_t len = p - tile_buf;
            memcpy(&client->write_buf[client->write_len], tile_buf, len);
            client->write_len += len;
        }
    }
    
    return 0; // Success
}
