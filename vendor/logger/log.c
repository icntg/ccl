/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* https://github.com/rxi/log.c */

#pragma warning(once:4996)
#define _CRT_SECURE_NO_WARNINGS

#include <string.h>
#include <tchar.h>
#include "log.h"

#define MAX_CALLBACKS 32

typedef struct st_callback {
    log_LogFn fn;
    void *udata;
    int level;
} Callback;

static struct {
    void *udata;
    log_LockFn lock;
    int level;
    bool quiet;
    Callback callbacks[MAX_CALLBACKS];
} L;

static const TCHAR *level_strings[] = {
        _T("TRACE"), _T("DEBUG"), _T("INFO"), _T("WARN"), _T("ERROR"), _T("FATAL")
};

#ifdef LOG_USE_COLOR
static const char* level_colors[] = {
  "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};
#endif


static void stdout_callback(LogEvent *ev) {
    TCHAR buf[16];
    buf[strftime(buf, sizeof(buf), _T("%H:%M:%S"), ev->time)] = _T('\0');
#ifdef LOG_USE_COLOR
    fprintf(
        (FILE *)ev->udata, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ",
        buf, level_colors[ev->level], level_strings[ev->level],
        ev->file, ev->line);
#else
    fprintf(
            (FILE *) ev->udata, "%s %-5s %s:%d: ",
            buf, level_strings[ev->level], ev->file, ev->line);
#endif
    vfprintf((FILE *) ev->udata, ev->fmt, ev->ap);
    fprintf((FILE *) ev->udata, "\n");
    fflush((FILE *) ev->udata);
}


static void file_callback(LogEvent *ev) {
    char buf[64];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ev->time)] = '\0';
    fprintf(
            (FILE *) ev->udata, "%s %-5s %s:%d: ",
            buf, level_strings[ev->level], ev->file, ev->line);
    vfprintf((FILE *) ev->udata, ev->fmt, ev->ap);
    fprintf((FILE *) ev->udata, "\n");
    fflush((FILE *) ev->udata);
}


static void lock(void) {
    if (L.lock) { L.lock(true, L.udata); }
}


static void unlock(void) {
    if (L.lock) { L.lock(false, L.udata); }
}


const char *log_level_string(int level) {
    return level_strings[level];
}


void log_set_lock(log_LockFn fn, void *udata) {
    L.lock = fn;
    L.udata = udata;
}


void log_set_level(int level) {
    L.level = level;
}


void log_set_quiet(bool enable) {
    L.quiet = enable;
}


int log_add_callback(log_LogFn fn, void *udata, int level) {
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (!L.callbacks[i].fn) {
            L.callbacks[i].fn = fn;
            L.callbacks[i].udata = udata;
            L.callbacks[i].level = level;
            //L.callbacks[i] = (Callback){ fn, udata, level };
            return 0;
        }
    }
    return -1;
}


int log_add_fp(FILE *fp, int level) {
    return log_add_callback(file_callback, fp, level);
}


static void init_event(LogEvent *ev, void *udata) {
    if (!ev->time) {
        time_t t = time(NULL);
        //localtime_s(ev->time, &t);
        ev->time = localtime(&t);
    }
    ev->udata = udata;
}


void log_log(int level, const char *file, int line, const char *fmt, ...) {
    LogEvent ev;
    memset(&ev, 0, sizeof(LogEvent));
    ev.fmt = fmt;
    ev.file = file;
    ev.line = line;
    ev.level = level;

    lock();

    if (!L.quiet && level >= L.level) {
        init_event(&ev, stderr);
                va_start(ev.ap, fmt);
        stdout_callback(&ev);
                va_end(ev.ap);
    }

    for (int i = 0; i < MAX_CALLBACKS && L.callbacks[i].fn; i++) {
        Callback *cb = &L.callbacks[i];
        if (level >= cb->level) {
            init_event(&ev, cb->udata);
                    va_start(ev.ap, fmt);
            cb->fn(&ev);
                    va_end(ev.ap);
        }
    }
    unlock();
}