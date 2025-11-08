#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

typedef struct dirent *(*readdir_t)(DIR *);

static readdir_t real_readdir(void) {
    static readdir_t fn = NULL;
    if (!fn) {
        fn = (readdir_t)dlsym(RTLD_NEXT, "readdir");
        if (!fn) {
            fprintf(stderr, "dlsym readdir failed\n");
            _exit(1);
        }
    }
    return fn;
}

static char *get_pattern(void) {
    char *p;
    p = getenv("HIDE_PATTERN");
    return p;
}

struct dirent *readdir(DIR *dirp) {
    readdir_t fn;
    char *pat;
    struct dirent *d;

    fn = real_readdir();
    if (!fn) {
        return NULL;
    }

    pat = get_pattern();
    while ((d = fn(dirp)) != NULL) {
        if (pat && strstr(d->d_name, pat)) {
            continue;
        }
        return d;
    }
    return NULL;
}

