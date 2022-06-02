#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include "zdbfs.h"
#include "cache.h"

#define UNW_LOCAL_ONLY
#include <libunwind.h>

//
// error handling/printing
//
void warns(char *help, char *value) {
    fprintf(stderr, "[-] %s: %s\n", help, value);
}

void dies(char *help, char *value) {
    warns(help, value);
    exit(EXIT_FAILURE);
}

//
// debug purpose
//
void zdbfs_system_fulldump(void *_data, size_t len) {
    uint8_t *data = _data;
    unsigned int i, j;

    printf("[*] data fulldump [%p -> %p] (%lu bytes)\n", data, data + len, len);
    printf("[*] 0x0000: ");

    for(i = 0; i < len; ) {
        printf("%02x ", data[i++]);

        if(i % 16 == 0) {
            printf("|");

            for(j = i - 16; j < i; j++)
                printf("%c", ((isprint(data[j]) ? data[j] : '.')));

            printf("|\n[*] 0x%04x: ", i);
        }
    }

    if(i % 16) {
        printf("%-*s |", 5 * (16 - (i % 16)), " ");

        for(j = i - (i % 16); j < len; j++)
            printf("%c", ((isprint(data[j]) ? data[j] : '.')));

        printf("%-*s|\n", 16 - ((int) len % 16), " ");
    }

    printf("\n");
}

void zdbfs_system_backtrace() {
	unw_cursor_t cursor;
	unw_context_t context;

	// grab the machine context and initialize the cursor
	if(unw_getcontext(&context) < 0)
		dies("backtrce", "cannot get local machine state");

	if(unw_init_local2(&cursor, &context, UNW_INIT_SIGNAL_FRAME) < 0)
		dies("backtrace", "cannot initialize cursor for local unwinding");

	// currently the IP is within backtrace() itself so this loop
	// deliberately skips the first frame.
	while(unw_step(&cursor) > 0) {
		unw_word_t offset, pc;
		char sym[4096];

		if(unw_get_reg(&cursor, UNW_REG_IP, &pc))
			dies("backtrace", "cannot read program counter");

		printf("0x%lx: ", pc);

		if(unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
			printf("(%s+0x%lx)\n", sym, offset);

        } else {
			printf("[no symbol name found]\n");
        }
	}
}

int zdbfs_system_signal(int signal, void (*function)(int)) {
    struct sigaction sig;
    int ret;

    sigemptyset(&sig.sa_mask);
    sig.sa_handler = function;
    sig.sa_flags = 0;

    if((ret = sigaction(signal, &sig, NULL)) == -1)
        zdbfs_sysfatal("sigaction");

    return ret;
}

void zdbfs_system_sighandler(int signal) {
    switch(signal) {
        case SIGUSR1:
            zdbfs_cache_stats(__zdbfs_instance);
            return;

        case SIGSEGV:
            fprintf(stderr, "[-] fatal: segmentation fault\n");
            zdbfs_system_backtrace();
            break;
        }

    // forward original error code
    exit(128 + signal);
}


