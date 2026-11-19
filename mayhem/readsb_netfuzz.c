// readsb_netfuzz.c — run ONE real readsb process on ONE input file, delivered through readsb's
// own input services (the code path a remote feeder/client reaches), then shut readsb down.
//
// readsb is a multi-threaded epoll daemon whose protocol readers (readBeast, readAscii,
// readAsterix, decodeSbsLine, the HTTP API, ...) are static and run against heavy global state,
// so they are reached the way an attacker reaches them: over a socket. readsb.c is compiled with
// -Dmain=readsb_main and this file supplies main():
//
//   readsb-netfuzz listen  <--net-...-port flag> <input> [readsb args...]
//       readsb listens on a unix socket for that service; we connect, send <input>, half-close,
//       read until readsb closes the client (it has consumed and processed every byte), then ask
//       readsb to exit via its own setExit().
//   readsb-netfuzz connect <protocol> <input> [readsb args...]
//       for services that only exist as outbound connectors (planefinder_in, gpsd_in): we listen
//       on 127.0.0.1:<ephemeral>, readsb connects with --net-connector, we send <input> likewise.
//   readsb-netfuzz state <input> [readsb args...]
//       <input> is a persistent-state blob (<--write-state dir>/internal_state/blob_00), loaded by
//       readInternalState() during startup; once readsb's network is up the load is done, exit.
//
// No timers: completion is signalled by readsb itself (closing the client / its listener being up).
// All scratch lives in a fresh mkdtemp() directory under $TMPDIR (or /tmp), removed at exit.
#define _GNU_SOURCE
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int readsb_main(int argc, char **argv);
void setExit(int arg);

enum { MODE_LISTEN, MODE_CONNECT, MODE_STATE };

static int mode;
static unsigned char *data;
static size_t data_len;
static char tmpdir[128];
static char sockpath[160];
static int listen_fd = -1;

static int rm_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw) {
    (void) sb; (void) flag; (void) ftw;
    remove(path);
    return 0;
}

static void cleanup(void) {
    if (tmpdir[0])
        nftw(tmpdir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void die(const char *what) {
    perror(what);
    exit(2);
}

static void send_and_drain(int fd) {
    size_t off = 0;
    while (off < data_len) {
        ssize_t n = send(fd, data + off, data_len - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break; // readsb dropped the client early: nothing more to deliver
        off += (size_t) n;
    }
    shutdown(fd, SHUT_WR);
    char buf[65536];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0 || (n < 0 && errno == EINTR))
            continue;
        break; // EOF: readsb processed the input and closed the client
    }
    close(fd);
}

static void *injector(void *arg) {
    (void) arg;
    int fd;
    if (mode == MODE_CONNECT) {
        do {
            fd = accept(listen_fd, NULL, NULL);
        } while (fd < 0 && errno == EINTR);
        if (fd < 0)
            die("accept");
    } else {
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, sockpath);
        // wait for readsb's listener to come up (it is created by readsb's decode thread)
        for (;;) {
            fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0)
                die("socket");
            if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0)
                break;
            close(fd);
            usleep(1000);
        }
    }
    if (mode == MODE_STATE)
        close(fd);
    else
        send_and_drain(fd);
    setExit(1);
    return NULL;
}

static void read_input(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        die(path);
    size_t cap = 65536;
    data = malloc(cap);
    size_t n;
    while ((n = fread(data + data_len, 1, cap - data_len, f)) > 0) {
        data_len += n;
        if (data_len == cap) {
            cap *= 2;
            data = realloc(data, cap);
        }
    }
    fclose(f);
}

static void write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f || (len && fwrite(buf, 1, len, f) != len) || fclose(f) != 0)
        die(path);
}

int main(int argc, char **argv) {
    if (argc < 3)
        goto usage;
    int first; // index of the first passthrough readsb argument
    const char *what = NULL;
    if (!strcmp(argv[1], "listen") && argc >= 4) {
        mode = MODE_LISTEN; what = argv[2]; read_input(argv[3]); first = 4;
    } else if (!strcmp(argv[1], "connect") && argc >= 4) {
        mode = MODE_CONNECT; what = argv[2]; read_input(argv[3]); first = 4;
    } else if (!strcmp(argv[1], "state")) {
        mode = MODE_STATE; read_input(argv[2]); first = 3;
    } else {
        goto usage;
    }

    const char *t = getenv("TMPDIR");
    if (!t || !*t || strlen(t) > 64)
        t = "/tmp";
    snprintf(tmpdir, sizeof(tmpdir), "%s/readsb-fuzz-XXXXXX", t);
    if (!mkdtemp(tmpdir))
        die("mkdtemp");
    atexit(cleanup);
    snprintf(sockpath, sizeof(sockpath), "%s/s", tmpdir);

    char **nargv = calloc(argc + 8, sizeof(char *));
    int n = 0;
    char sockarg[200], conarg[64], path[200];
    snprintf(sockarg, sizeof(sockarg), "unix:%s", sockpath);
    nargv[n++] = "readsb";
    nargv[n++] = "--net-only";
    if (mode == MODE_LISTEN) {
        nargv[n++] = (char *) what;
        nargv[n++] = sockarg;
    } else if (mode == MODE_CONNECT) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t sl = sizeof(sa);
        if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *) &sa, sizeof(sa)) != 0
                || listen(listen_fd, 4) != 0 || getsockname(listen_fd, (struct sockaddr *) &sa, &sl) != 0)
            die("listen");
        snprintf(conarg, sizeof(conarg), "127.0.0.1,%d,%s", ntohs(sa.sin_port), what);
        nargv[n++] = "--net-connector";
        nargv[n++] = conarg;
    } else {
        snprintf(path, sizeof(path), "%s/internal_state", tmpdir);
        if (mkdir(path, 0700) != 0)
            die(path);
        snprintf(path, sizeof(path), "%s/internal_state/blob_00", tmpdir);
        write_file(path, data, data_len);
        nargv[n++] = "--write-state";
        nargv[n++] = tmpdir;
        nargv[n++] = "--net-ri-port"; // readiness: the network starts after the state is loaded
        nargv[n++] = sockarg;
    }
    for (int i = first; i < argc; i++)
        nargv[n++] = argv[i];
    nargv[n] = NULL;

    pthread_t th;
    if (pthread_create(&th, NULL, injector, NULL) != 0)
        die("pthread_create");
    pthread_detach(th);
    return readsb_main(n, nargv);

usage:
    fprintf(stderr,
            "usage: %s listen <--net-...-port> <input> [readsb args...]\n"
            "       %s connect <protocol> <input> [readsb args...]\n"
            "       %s state <blob> [readsb args...]\n", argv[0], argv[0], argv[0]);
    return 2;
}
