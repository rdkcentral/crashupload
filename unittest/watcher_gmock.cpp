/**
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * @file watcher_gmock.cpp
 * @brief Mock syscall wrappers for inotify-minidump-watcher L1 tests
 */

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fnmatch.h>
#include <limits.h>
#include <signal.h>
#include <string>
#include <sys/inotify.h>
#include <vector>

struct FakeRead {
    bool fail;
    bool zero_count;
    int err;
    int wd;
    uint32_t mask;
    std::string name;
};

static int g_init_ret = 1;
static int g_init_err = 0;
static int g_watch_ret = 2;
static int g_watch_err = 0;
static std::vector<FakeRead> g_reads;
static size_t g_read_i = 0;
static std::vector<int> g_closes;
static size_t g_close_i = 0;
static int g_close_err = 0;
static int g_system_ret = 0;
static char g_last_cmd[PATH_MAX];
static int g_printf_fail = 0;
static int g_fnmatch_override = 0;
static int g_fnmatch_value = 0;
static int g_sigaction_ret = 0;
static int g_sigaction_err = 0;

extern "C" {

void watcher_mock_reset(void)
{
    g_init_ret = 1;
    g_init_err = 0;
    g_watch_ret = 2;
    g_watch_err = 0;
    g_reads.clear();
    g_read_i = 0;
    g_closes.clear();
    g_close_i = 0;
    g_close_err = 0;
    g_system_ret = 0;
    memset(g_last_cmd, 0, sizeof(g_last_cmd));
    g_printf_fail = 0;
    g_fnmatch_override = 0;
    g_fnmatch_value = 0;
    g_sigaction_ret = 0;
    g_sigaction_err = 0;
}

void watcher_mock_set_inotify_init(int ret, int err)
{
    g_init_ret = ret;
    g_init_err = err;
}

void watcher_mock_set_add_watch(int ret, int err)
{
    g_watch_ret = ret;
    g_watch_err = err;
}

void watcher_mock_push_read_event(int wd, uint32_t mask, const char *name)
{
    FakeRead ev;
    ev.fail = false;
    ev.zero_count = false;
    ev.err = 0;
    ev.wd = wd;
    ev.mask = mask;
    ev.name = (name != NULL) ? name : "";
    g_reads.push_back(ev);
}

void watcher_mock_push_read_zero(void)
{
    FakeRead ev;
    ev.fail = false;
    ev.zero_count = true;
    ev.err = 0;
    ev.wd = -1;
    ev.mask = 0;
    ev.name.clear();
    g_reads.push_back(ev);
}

void watcher_mock_push_read_fail(int err)
{
    FakeRead ev;
    ev.fail = true;
    ev.zero_count = false;
    ev.err = err;
    ev.wd = -1;
    ev.mask = 0;
    ev.name.clear();
    g_reads.push_back(ev);
}

void watcher_mock_push_close(int ret)
{
    g_closes.push_back(ret);
}

void watcher_mock_set_close_errno(int err)
{
    g_close_err = err;
}

void watcher_mock_set_system_ret(int ret)
{
    g_system_ret = ret;
}

const char *watcher_mock_last_system_cmd(void)
{
    return g_last_cmd;
}

void watcher_mock_set_printf_fail(int fail)
{
    g_printf_fail = fail;
}

void watcher_mock_set_fnmatch_result(int use_override, int value)
{
    g_fnmatch_override = use_override;
    g_fnmatch_value = value;
}

void watcher_mock_set_sigaction_ret(int ret, int err)
{
    g_sigaction_ret = ret;
    g_sigaction_err = err;
}

int mock_inotify_init(void)
{
    if (g_init_ret < 0)
    {
        errno = g_init_err ? g_init_err : EMFILE;
    }
    return g_init_ret;
}

int mock_inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
    (void)fd;
    (void)pathname;
    (void)mask;
    if (g_watch_ret < 0)
    {
        errno = g_watch_err ? g_watch_err : ENOENT;
    }
    return g_watch_ret;
}

ssize_t mock_read(int fd, void *buf, size_t count)
{
    (void)fd;
    if (g_read_i >= g_reads.size())
    {
        errno = EAGAIN;
        return -1;
    }

    const FakeRead &ev = g_reads[g_read_i++];
    if (ev.fail)
    {
        errno = ev.err ? ev.err : EIO;
        return -1;
    }
    if (ev.zero_count)
    {
        return 0;
    }

    if (buf == NULL || count < sizeof(struct inotify_event))
    {
        errno = EINVAL;
        return -1;
    }

    memset(buf, 0, count);
    struct inotify_event *event_ptr = static_cast<struct inotify_event *>(buf);
    event_ptr->wd = ev.wd;
    event_ptr->mask = ev.mask;
    event_ptr->cookie = 0;

    if (ev.name.empty())
    {
        event_ptr->len = 0;
        return static_cast<ssize_t>(sizeof(struct inotify_event));
    }

    size_t name_bytes = ev.name.size() + 1;
    size_t max_name = (count > sizeof(struct inotify_event))
                          ? (count - sizeof(struct inotify_event))
                          : 0;
    if (name_bytes > max_name)
    {
        name_bytes = max_name;
    }
    event_ptr->len = static_cast<uint32_t>(name_bytes);
    if (name_bytes > 0)
    {
        memcpy(event_ptr->name, ev.name.c_str(), name_bytes - 1);
        event_ptr->name[name_bytes - 1] = '\0';
    }
    return static_cast<ssize_t>(sizeof(struct inotify_event) + name_bytes);
}

int mock_close(int fd)
{
    (void)fd;
    if (g_close_i >= g_closes.size())
    {
        return 0;
    }
    int ret = g_closes[g_close_i++];
    if (ret < 0)
    {
        errno = g_close_err ? g_close_err : EIO;
    }
    return ret;
}

int mock_system(const char *command)
{
    if (command != NULL)
    {
        strncpy(g_last_cmd, command, sizeof(g_last_cmd) - 1);
        g_last_cmd[sizeof(g_last_cmd) - 1] = '\0';
    }
    if (g_system_ret < 0)
    {
        errno = EAGAIN;
    }
    return g_system_ret;
}

int mock_printf(const char *fmt, ...)
{
    if (g_printf_fail)
    {
        (void)fmt;
        errno = EIO;
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

int mock_fnmatch(const char *pattern, const char *string, int flags)
{
    if (g_fnmatch_override)
    {
        return g_fnmatch_value;
    }
    return fnmatch(pattern, string, flags);
}

int mock_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    (void)signum;
    (void)act;
    (void)oldact;
    if (g_sigaction_ret < 0)
    {
        errno = g_sigaction_err ? g_sigaction_err : EINVAL;
    }
    return g_sigaction_ret;
}

}
