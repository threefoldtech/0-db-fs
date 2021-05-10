#ifndef ZDBFS_SYSTEM_H
    #define ZDBFS_SYSTEM_H

    void zdbfs_fulldump(void *_data, size_t len);
    void zdbfs_system_backtrace();
    void zdbfs_system_sighandler(int signal);
    int zdbfs_system_signal(int signal, void (*function)(int));

    void warns(char *help, char *value);
    void dies(char *help, char *value);
#endif
