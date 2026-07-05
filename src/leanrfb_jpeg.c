#include "leanrfb_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <jpeglib.h>
#include <setjmp.h>

struct my_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

static void my_error_exit(j_common_ptr cinfo) {
    struct my_error_mgr* myerr = (struct my_error_mgr*)cinfo->err;
    // Format and output error message to stderr
    char buffer[JMSG_LENGTH_MAX];
    (*cinfo->err->format_message)(cinfo, buffer);
    fprintf(stderr, "[VNC JPEG ERROR] %s\n", buffer);
    longjmp(myerr->setjmp_buffer, 1);
}

int compress_jpeg(const uint32_t* src, int w, int h, int stride, uint8_t** out_buf, unsigned long* out_size, int quality) {
    struct jpeg_compress_struct cinfo;
    struct my_error_mgr jerr;
    
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;
    if (setjmp(jerr.setjmp_buffer)) {
        jpeg_destroy_compress(&cinfo);
        return -1;
    }
    
    jpeg_create_compress(&cinfo);
    
    // Configures libjpeg to compress into a dynamic memory buffer (*out_buf)
    jpeg_mem_dest(&cinfo, out_buf, out_size);
    
    cinfo.image_width = w;
    cinfo.image_height = h;
    
    // libjpeg-turbo extensions (JCS_EXT_BGRX allows direct compression of 32-bit BGRA pixels without copy)
    cinfo.input_components = 4;
    cinfo.in_color_space = JCS_EXT_BGRX;
    
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, quality, TRUE);
    
    jpeg_start_compress(&cinfo, TRUE);
    
    while (cinfo.next_scanline < cinfo.image_height) {
        const uint32_t* src_row = src + cinfo.next_scanline * stride;
        JSAMPROW row_pointer[1] = { (JSAMPROW)src_row };
        jpeg_write_scanlines(&cinfo, row_pointer, 1);
    }
    
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    return 0;
}
