#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef CHECKNS_HAVE_LIBMOUNT
#include <libmount/libmount.h>
#endif

static int ndevids;
static dev_t *devids;
static int nsuspects;

static const char *get_typnam(unsigned char typ) {
    char *nam;
    switch (typ) {
        case DT_BLK: nam = "blk"; break;
        case DT_CHR: nam = "char"; break;
        case DT_FIFO: nam = "fifo"; break;
        case DT_SOCK: nam = "sock"; break;
        case DT_LNK: nam = "link"; break;
        case DT_DIR: nam = "dir"; break;
        case DT_REG: nam = "file"; break;
        default:
        case DT_UNKNOWN: nam = "unknown"; break;
    }
    return nam;
}

static const char *strdev(dev_t dev) {
    static char buf[128];
    int n = snprintf(buf, sizeof(buf), "%u:%u|%lx", major(dev), minor(dev), dev);
    assert(n > 0 && n < sizeof(buf));
    return buf;
}

#define INVALID_DEV 0
// parses a devid in the form maj:min (e.g. "254:1") or in hex form (e.g. "fe01")
static dev_t parse_dev(const char *devstr) {
    assert(devstr);

    bool colon = false;
    char c;
    size_t i = 0;

    while ((c = devstr[i]) != '\0') {
        if (c == ':') {
            colon = true;
            break;
        }
        i++;
    }

    const char *s;
    char *end;

    if (colon) {
        // parse format maj:min (e.g. "254:1")
        s = devstr;
        if (*s == '-' || *s == ':' || *s == '\0') {
            return INVALID_DEV;  // devids cannot be negative
        }
        unsigned int maj = strtoul(s, &end, 10);
        if (*end != ':') {
            return INVALID_DEV;  // we should encounter the colon after maj in maj:min
        }

        s = &devstr[i + 1];
        if (*s == '-' || *s == '\0') {
            return INVALID_DEV;  // there should be a min in maj:min
        }
        unsigned int min = strtoul(s, &end, 10);
        if (*end != '\0') {
            return INVALID_DEV;  // invalid devstr as there should be nothing after maj:min
        }

        dev_t dev = makedev(maj, min);
        assert(dev != INVALID_DEV);
        return dev;
    } else {
        // parse hex format (e.g. "fe03")
        s = devstr;
        if (*s == '-' || *s == '\0') {
            return INVALID_DEV;  // devids cannot be negative
        }
        dev_t dev = strtoul(s, &end, 16);
        if (*end != '\0') {
            return INVALID_DEV;  // there should be no more
        }

        assert(dev != INVALID_DEV);
        return dev;
    }
}

static bool is_suspect_dev(const dev_t dev) {
    for (int i = 0; i < ndevids; i++) {
        if (dev == devids[i]) {
            return true;
        }
    }
    return false;
}

struct suspect {
    bool directory;
    bool readable;
    bool writable;
    dev_t dev;
};

static const char *strsuspect(const struct suspect *sus) {
    static char buf[256];
    assert(sus);

    const char *prefix = "";
    if (sus->directory) {
        prefix = "directory ";
    } else if (sus->readable && sus->writable) {
        prefix = "read+writable ";
    } else if (sus->readable) {
        prefix = "readable ";
    } else if (sus->writable) {
        prefix = "writable ";
    }

    int n = snprintf(buf, sizeof(buf), "SUSPECT %s(dev %s)", prefix, strdev(sus->dev));
    assert(n > 0 && n < sizeof(buf));
    return buf;
}

static bool is_suspect_fd(const int fd, struct stat *statbuf, struct suspect *sus) {
    assert(statbuf);
    assert(sus);

    memset(sus, 0, sizeof(struct suspect));

    int r = fstat(fd, statbuf);
    if (r != 0) {
        return false;  // stat failed
    }

    sus->dev = statbuf->st_dev;
    return is_suspect_dev(sus->dev);
}

static bool is_suspect_path_statted(const char *path, const struct stat *statbuf,
                                    struct suspect *sus) {
    assert(statbuf);
    assert(sus);

    memset(sus, 0, sizeof(struct suspect));

    sus->dev = statbuf->st_dev;
    if (is_suspect_dev(sus->dev)) {
        // we got a suspect, try opening it
        int fd;

        fd = open(path, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) {
            sus->directory = true;
            close(fd);
        } else {
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                sus->readable = true;
                close(fd);
            }

            fd = open(path, O_WRONLY);
            if (fd >= 0) {
                sus->writable = true;
                close(fd);
            }
        }

        return true;
    }

    return false;
}

/*  // currently unused
static bool is_suspect_path(const char *path, struct stat *statbuf, struct suspect *sus) {
    assert(statbuf);
    assert(sus);

    int r = stat(path, statbuf);
    if (r != 0) {
        return false;  // stat failed, just skip
    }

    return is_suspect_path_statted(path, statbuf, sus);
}
*/

#define NTRACKERS 1024
#define TRACKER_PATHLEN 1024

struct tracker {
    dev_t dev;
    ino_t ino;
    char path[TRACKER_PATHLEN];
};

static struct tracker trackers[NTRACKERS];

// recursive helper for check_fstree
static void check_fstree_helper(const char *basepath, int depth) {
    static struct stat statbuf;

    DIR *dir;
    struct dirent *entry;

    dir = opendir(basepath);
    if (dir == NULL) {
        return;  // opendir of basepath failed, just skip
    }

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        unsigned char typ = entry->d_type;

        if (typ == DT_DIR) {
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                goto NEXTENT;
            }
        }

        char *path = trackers[depth].path;
        if (strcmp(basepath, "/") == 0) {
            basepath = "";
        }
        if (snprintf(path, TRACKER_PATHLEN, "%s/%s", basepath, name) >= TRACKER_PATHLEN) {
            fprintf(stderr, "[check_fstree] error: path too long: %s/%s\n", basepath, name);
            goto NEXTENT;
        }

        int r = stat(path, &statbuf);
        if (r != 0) {
            goto NEXTENT;  // stat of path failed, just skip
        }

        dev_t dev = statbuf.st_dev;
        ino_t ino = statbuf.st_ino;

        struct suspect sus;
        if (is_suspect_path_statted(path, &statbuf, &sus)) {
            printf("[check_fstree] %s: %s %s\n", strsuspect(&sus),
                   get_typnam(typ), path);
            nsuspects++;
            goto NEXTENT;  // don't investigate subtrees of suspects
        }

        if (typ == DT_DIR) {
            if (depth >= NTRACKERS - 1) {
                fprintf(stderr, "[check_fstree] error: max depth reached: %s\n", path);
                goto NEXTENT;
            }

            for (int i = 0; i < depth; i++) {
                if (trackers[i].dev == dev && trackers[i].ino == ino) {
                    goto NEXTENT;  // this is a dupe, break cycles
                }
            }

            trackers[depth].dev = dev;
            trackers[depth].ino = ino;
            check_fstree_helper(path, depth + 1);
        }
NEXTENT:;
    }
    closedir(dir);
}

// checks the filesystem tree starting at / by recursively walking
static void check_fstree(void) {
    static struct stat statbuf;

    fprintf(stderr, "\n[check_fstree] Checking filesystem tree...\n");

    int r = stat("/", &statbuf);
    if (r != 0) {
        char *err = strerror(errno);
        fprintf(stderr, "[check_fstree] error: failed to stat root directory: %s\n", err);
        return;
    }

    struct suspect sus;
    if (is_suspect_path_statted("/", &statbuf, &sus)) {
        printf("[check_fstree] %s: / (root directory)\n", strsuspect(&sus));
        nsuspects++;
        return;  // don't investigate anymore if root directory is already suspect
    }

    trackers[0].dev = statbuf.st_dev;
    trackers[0].ino = statbuf.st_ino;
    check_fstree_helper("/", 1);
}

#define NPOLLFDS 1024
// checks open file descriptors
static void check_openfds(void) {
    static struct pollfd pollfds[NPOLLFDS];
    static struct stat statbuf;

    fprintf(stderr, "\n[check_openfds] Checking open file descriptors...\n");

    // look for open file descriptors NPOLLFDS at a time
    int maxfd = getdtablesize();
    int cur = 0;
    while (cur < maxfd) {
        memset(pollfds, 0, sizeof(pollfds));
        int n = 0;
        for (n = 0; n < NPOLLFDS && (cur + n) < maxfd; n++) {
            pollfds[n].fd = cur + n;
        }

        int r = poll(pollfds, n, 0);
        if (r < 0) {
            fprintf(stderr, "[check_openfds] error: failed to poll for open fds\n");
            return;
        }

        for (int i = 0; i < n; i++) {
            if (!(pollfds[i].revents & POLLNVAL)) {
                // found open file descriptor
                int fd = pollfds[i].fd;
                struct suspect sus;
                if (is_suspect_fd(fd, &statbuf, &sus)) {
                    printf("[check_openfds] %s: open fd %d\n",
                           strsuspect(&sus), fd);
                    nsuspects++;
                }
            }
        }

        cur += n;
    }
}

#define CWDPATHLEN 1024
/* checks current working directory and parents
   NOTE: this funciton may be called as a subroutine of another check function,
         if so, pass an appropriate modname, otherwise pass NULL */
static void check_cwd(const char *modname) {
    static char pathbuf[CWDPATHLEN];
    static struct stat statbuf;

    if (!modname) {
        modname = "check_cwd";
        fprintf(stderr, "\n[check_cwd] Checking current working directory and parents...\n");
    }

    int r = stat(".", &statbuf);
    if (r < 0) {
        fprintf(stderr, "[%s] error: failed to stat current directory\n", modname);
        return;
    }

    struct suspect sus;
    if (is_suspect_path_statted(".", &statbuf, &sus)) {
        char *path = getcwd(pathbuf, sizeof(pathbuf));
        if (path) {
            printf("[%s] %s: . (%s) (current working directory)\n",
                   modname, strsuspect(&sus), path);
        } else {
            printf("[%s] %s: . (current working directory)\n",
                   modname, strsuspect(&sus));
        }
        nsuspects++;
    }

    dev_t dev;
    ino_t ino;
    size_t n = 0;
    memset(pathbuf, 0, sizeof(pathbuf));

    do {
        dev = statbuf.st_dev;
        ino = statbuf.st_ino;

        if (n >= sizeof(pathbuf) / 3 + 1) {
            fprintf(stderr, "[check_cwd] error: path too long: %s/..\n",
                    pathbuf);
            return;
        }

        pathbuf[3*n] = '.';
        pathbuf[3*n + 1] = '.';
        pathbuf[3*n + 2] = '\0';

        r = stat(pathbuf, &statbuf);
        if (r < 0) {
            return;  // stat failed, just stop
        }

        struct suspect sus;
        if (is_suspect_path_statted(".", &statbuf, &sus)) {
            printf("[%s] %s: %s "
                   "(parent %ld of current working directory)\n",
                   modname, strsuspect(&sus), pathbuf, n);
            nsuspects++;
            break;  // don't investigate more parents of suspects
        }

        pathbuf[3*n + 2] = '/';
        n++;
    } while (statbuf.st_dev != dev || statbuf.st_ino != ino);
}

// check /proc/self/mountinfo for leaky mounts
static void check_mountinfo(void) {
#ifdef CHECKNS_HAVE_LIBMOUNT
    fprintf(stderr, "\n[check_mountinfo] Checking /proc/self/mountinfo for "
                    "problematic mounts...\n");

    struct libmnt_table *tb = mnt_new_table();
    struct libmnt_iter *it = mnt_new_iter(MNT_ITER_FORWARD);
    if (tb == NULL || it == NULL) {
        fprintf(stderr, "\n[check_mountinfo] error: failed to initialize libmount\n");
        return;
    }

    int r;
    r = mnt_table_parse_mtab(tb, "/proc/self/mountinfo");
    if (r < 0) {
        fprintf(stderr, "\n[check_mountinfo] error: failed to parse /proc/self/mountinfo\n");
        return;
    }

    struct libmnt_fs *fs;
    r = mnt_table_first_fs(tb, &fs);
    assert(r == 0);

    r = mnt_table_set_iter(tb, it, fs);
    assert(r == 0);

    do {
        const dev_t dev = mnt_fs_get_devno(fs);
        assert(dev > 0);

        const char *optfields = mnt_fs_get_optional_fields(fs);
        const char *susopt = "";
        if (optfields) {
            if (strstr(optfields, "shared")) {
                susopt = "shared ";
            } else if (strstr(optfields, "master")) {
                susopt = "slave ";
            }
        }

        if (is_suspect_dev(dev)) {
            const char *fstype = mnt_fs_get_fstype(fs);
            assert(fstype);
            const char *targ = mnt_fs_get_target(fs);
            assert(targ);

            printf("[check_mountinfo] SUSPECT %smount (dev %s): [%s] %s\n",
                   susopt, strdev(dev), fstype, targ);
        } else if (*susopt != '\0') {
            const char *fstype = mnt_fs_get_fstype(fs);
            assert(fstype);
            const char *targ = mnt_fs_get_target(fs);
            assert(targ);

            fprintf(stderr, "[check_mountinfo] WARNING found %smount: [%s] %s\n",
                    susopt, fstype, targ);
        }

        r = mnt_table_next_fs(tb, it, &fs);
        assert(r >= 0);
    } while (r == 0);

    mnt_free_iter(it);
    mnt_free_table(tb);
#else
    fprintf(stderr, "\n[check_mountinfo] Skipping (not built with libmount)...\n");
#endif
}

/* check for classic chroot escape (container should not be using chroot for
   isolation)

   NOTE: potentially changes working directory */
static void check_chroot(void) {

    fprintf(stderr, "\n[check_chroot] Checking for classic chroot escape...\n");

    int cwd = open(".", O_DIRECTORY);
    if (cwd < 0) {
        fprintf(stderr, "[check_chroot] error: failed to open current directory\n");
        return;
    }

    int r = mkdir("check_chroot", 0777);
    if (r != 0) {
        close(cwd);
        fprintf(stderr, "[check_chroot] error: unable to mkdir in working directory\n");
        return;
    }

    r = chroot("check_chroot");
    if (r != 0) {
        close(cwd);
        rmdir("check_chroot");
        return;  // chroot failed, just skip
    }

    r = fchdir(cwd);
    if (r != 0) {
        close(cwd);
        return;  // fchdir failed just skip
    }

    close(cwd);
    rmdir("check_chroot");

    fprintf(stderr, "[check_chroot] WARNING re-chroot and fchdir successful, "
                    "outside parent directories may now be accessible\n");
    check_cwd("check_chroot");
}

static void check_all(void) {
    check_openfds();
    check_cwd(NULL);
    check_mountinfo();
    check_fstree();
    check_chroot();
}

struct userns_childarg {
    int pipefd[2];
};

static int userns_child_func(void *rawarg) {
    fprintf(stderr, "User namespace child running\n");

    struct userns_childarg *arg = (struct userns_childarg *) rawarg;

    // wait for parent to set uid_map/gid_map
    close(arg->pipefd[1]);
    char c;
    ssize_t nr = read(arg->pipefd[0], &c, 1);
    assert(nr == 0);
    close(arg->pipefd[0]);

    int r;
    pid_t pid = getpid();
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    r = getresuid(&ruid, &euid, &suid);
    assert(r == 0);
    r = getresgid(&rgid, &egid, &sgid);
    assert(r == 0);
    fprintf(stderr, "Current pid:%d resuid:%d/%d/%d resgid:%d/%d/%d\n",
            pid, ruid, euid, suid, rgid, egid, sgid);

    nsuspects = 0;
    check_all();

    fprintf(stderr, "\nFound %d suspect(s) (with a new user namespaces).\n", nsuspects);
    return nsuspects != 0;
}

static int userns_fail(const char *msg, pid_t child_pid) {
    fprintf(stderr, "User namespace attempt failed: %s\n", msg);
    if (child_pid > 0) {
        kill(child_pid, SIGTERM);
    }
    return -1;
}

// returns -1 on error, 0 if no suspects, 1 if suspects
static int userns_try(uid_t euid, gid_t egid) {
    fprintf(stderr, "\nAttempting additional checks in a new user namespace...\n");

    int r;
    struct userns_childarg arg;

    r = pipe(arg.pipefd);
    if (r != 0) {
        return userns_fail("could not create pipe", 0);
    }

    char *stack = (char *) malloc(256 * 1024);
    assert(stack);
    char *stack_top = stack + 256 * 1024;

    const int flags = \
        CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | \
        CLONE_NEWNET | CLONE_NEWCGROUP | SIGCHLD;
    pid_t child_pid = clone(userns_child_func, stack_top, flags, &arg);
    if (child_pid <= 0) {
        perror("huh");
        return userns_fail("could not clone child", 0);
    }

    // uid_map, setgroups, and gid_map stuff
    {
        static char mapbuf[128];
        ssize_t w;

        // uid_map
        r = snprintf(mapbuf, sizeof(mapbuf), "/proc/%d/uid_map", child_pid);
        assert(r > 0 && r < sizeof(mapbuf));
        int uidmap = open(mapbuf, O_RDWR);
        if (uidmap < 0) {
            return userns_fail("could not open uid_map", child_pid);
        }

        r = snprintf(mapbuf, sizeof(mapbuf), "0 %d 1\n", euid);
        assert(r > 0 && r < sizeof(mapbuf));
        w = write(uidmap, mapbuf, r);
        if (w != r) {
            close(uidmap);
            return userns_fail("could not write uid_map", child_pid);
        }
        close(uidmap);

        // setgroups (write "deny" to allow us to write gid_map)
        r = snprintf(mapbuf, sizeof(mapbuf), "/proc/%d/setgroups", child_pid);
        assert(r > 0 && r < sizeof(mapbuf));
        int sgfd = open(mapbuf, O_RDWR);
        if (sgfd < 0 && errno != ENOENT) {  // ENOENT means no need for "deny" for gid_map (Linux <3.19)
            return userns_fail("could not open setgroups to write 'deny'", child_pid);
        }

        const char *deny = "deny";
        w = write(sgfd, deny, strlen(deny));
        if (w != strlen(deny)) {
            close(sgfd);
            return userns_fail("could not write 'deny' to setgroups", child_pid);
        }
        close(sgfd);

        // gid_map
        r = snprintf(mapbuf, sizeof(mapbuf), "/proc/%d/gid_map", child_pid);
        assert(r > 0 && r < sizeof(mapbuf));
        int gidmap = open(mapbuf, O_RDWR);
        if (gidmap < 0) {
            return userns_fail("could not open gid_map", child_pid);
        }

        r = snprintf(mapbuf, sizeof(mapbuf), "0 %d 1\n", egid);
        assert(r > 0 && r < sizeof(mapbuf));
        w = write(gidmap, mapbuf, r);
        if (w != r) {
            close(gidmap);
            return userns_fail("could not write gid_map", child_pid);
        }
        close(gidmap);
    }

    // tell child we have set uid_map/gid_map
    close(arg.pipefd[1]);

    while (1) {
        int status;
        pid_t wp = waitpid(child_pid, &status, 0);
        if (wp < 0) {
            assert(errno == EINTR);  // ECHILD should not happen
            continue;
        } else {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            } else {
                return userns_fail("child exited abnormally", 0);
            }
        }
    }
}

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-h] [DEVID ...]\n", progname);
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 2;
    }

    if (argc < 2) {
        /* try and read devids from configuration file /checkns.conf
           (should just be formatted as newline-delimitted list of devids) */
        FILE *conf_file = fopen("/checkns.conf", "r");
        if (conf_file == NULL) {
            print_usage("checkns");
            fprintf(stderr, "Failed to open config file /checkns.conf\n");
            fprintf(stderr, "Either provide DEVIDs in that config file "
                            "(newline-delimited) or as arguments\n");
            return 2;
        }

        size_t capacity = 32;
        ndevids = 0;
        devids = calloc(capacity, sizeof(dev_t));
        assert(devids != NULL);

        size_t linesz = 0;
        char *line = NULL;
        ssize_t nread;
        while ((nread = getline(&line, &linesz, conf_file)) != -1) {
            char *s = line;
            while (*s != '\0') {
                if (*s == '\n') {
                    *s = '\0';
                }
                s++;
            }

            dev_t dev = parse_dev(line);
            if (dev == INVALID_DEV) {
                fprintf(stderr, "Could not parse devid from config file line: %s\n",
                        line);
                fclose(conf_file);
                return 2;
            }
            if (ndevids == capacity) {
                if (ndevids >= 1024) {  // should not have a ridiculous number of devs
                    fprintf(stderr, "Too many devids in config file!\n");
                    return 2;
                }
                capacity *= 2;
                devids = reallocarray(devids, capacity, sizeof(dev_t));
                assert(devids != NULL);
            }
            devids[ndevids] = dev;
            fprintf(stderr, "Loaded (from config file) devid[%d]: %s\n",
                    ndevids, strdev(dev));
            ndevids++;
        }
        free(line);
        fclose(conf_file);
    } else {
        // try and parse devids from argv arguments
        const int devid_start_idx = 1;
        ndevids = argc - devid_start_idx;
        assert(ndevids > 0);

        devids = calloc(ndevids, sizeof(dev_t));
        assert(devids != NULL);

        for (int i = devid_start_idx; i < argc; i++) {
            dev_t dev = parse_dev(argv[i]);
            if (dev == INVALID_DEV) {
                fprintf(stderr, "Could not parse devid from arg: %s\n", argv[i]);
                return 2;
            }
            devids[i - devid_start_idx] = dev;
            fprintf(stderr, "Loaded (from args) devid[%d]: %s\n",
                    i - devid_start_idx, strdev(dev));
        }
    }

    // try and get root back (e.g. if it was dropped improperly)
    setresgid(0, 0, 0);
    setresuid(0, 0, 0);
    setegid(0);
    seteuid(0);
    setfsuid(0);

    int r;
    pid_t pid = getpid();
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    r = getresuid(&ruid, &euid, &suid);
    assert(r == 0);
    r = getresgid(&rgid, &egid, &sgid);
    assert(r == 0);
    fprintf(stderr, "\nCurrent pid:%d resuid:%d/%d/%d resgid:%d/%d/%d\n",
            pid, ruid, euid, suid, rgid, egid, sgid);

    check_all();

    fprintf(stderr, "\nFound %d suspect(s).\n", nsuspects);

    // try again with user namespace (where we'll have some sort of root)
    r = userns_try(euid, egid);

    int ret = (nsuspects != 0);
    if (r == -1) {
        fprintf(stderr, "\n");
    } else {
        ret = (ret || r);
    }
    fprintf(stderr, "Previously found %d suspect(s) (without a new user namespace).\n", nsuspects);
    return ret;
}
