/**
 * MIT License
 * 
 * Copyright (c) 2023 Alex Chen
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdint.h>

#ifdef BASE64_DEBUG

#include <stdarg.h>
#include <stdio.h>

#endif

#ifdef BASE64_DEBUG

/* Logging function for debug. */
#define BASE64_LOG(fmt, ...)  printf(fmt, ##__VA_ARGS__)

/* Assertion macro used in the APIs. */
#define BASE64_ASSERT(expr)   \
    if (!(expr)) { BASE64_LOG("[BASE64] %s:%d: assertion failed: \"%s\"\n", \
        __FILE__, __LINE__, #expr); while (1);};

#else

/* Assertion macro used in the APIs. */
#define BASE64_ASSERT(expr)

#endif

/* All is well. */
#define BASE64_OK                       0

/* Encountered an invalid encoding character. */
#define BASE64_ERR_BAD_ENC_CHAR         -1

/* Invalid size of the encoded data. */
#define BASE64_ERR_BAD_ENC_SIZE         -2

/* Invalid padding of the encoded data. */
#define BASE64_ERR_BAD_ENC_PADDING      -3

uint32_t base64_error_param(void);

const char *base64_res2str(int res);

int base64_encode(void *buff, const void *data, int size);

int base64_decode(void *buff, const void *data, int size);

int base64_urlsafe_encode(void *buff, const void *data, int size);

int base64_urlsafe_decode(void *buff, const void *data, int size);

#endif