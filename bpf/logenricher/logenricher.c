// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/iov_iter.h>
#include <common/trace_common.h>
#include <common/trace_util.h>
#include <common/tracing.h>
#include <common/scratch_mem.h>
#include <common/strings.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>
#include <pid/pid_helpers.h>

#include <logenricher/path_resolver.h>
#include <logenricher/types.h>

#include <logenricher/maps/log_enricher_pids.h>
#include <logenricher/maps/log_events.h>
#include <logenricher/maps/pid_fd.h>
#include <logenricher/maps/zeros.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SCRATCH_MEM_SIZED(log_event, k_log_event_max_size);

static __always_inline bool pid_tracked(const struct task_struct *task) {
    u32 ns_pid = 0;
    u32 ns_ppid = 0;
    u32 ns_id = 0;

    ns_pid_ppid(task, (int *)&ns_pid, (int *)&ns_ppid, &ns_id);

    u64 key = ((u64)ns_id << 32) | ns_pid;

    u8 *tracked = bpf_map_lookup_elem(&log_enricher_pids, &key);
    if (tracked != NULL) {
        return true;
    }

    key = ((u64)ns_id << 32) | ns_ppid;

    tracked = bpf_map_lookup_elem(&log_enricher_pids, &key);
    return tracked != NULL;
}

static __always_inline int
__write(struct kiocb *iocb, struct iov_iter *from, const int fd, const struct task_struct *task) {
    iovec_iter_ctx iov_ctx;
    get_iovec_ctx(&iov_ctx, (struct iov_iter___dummy *)from);

    if (iov_ctx.iter_type != ITER_UBUF) {
        bpf_dbg_printk("logenricher: unsupported iter_type %d", iov_ctx.iter_type);
        return 0;
    }

    size_t count = BPF_CORE_READ(from, count);
    const long offset = bpf_core_field_offset(struct iov_iter, count) - 8;

    struct iovec iov = {};
    bpf_probe_read(&iov, sizeof(iov), (char *)from + offset);

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    pid_key_t pk = {};
    task_tid(&pk);
    trace_key_t t_key = {};
    trace_key_from_pid_tid_with_p_key(&t_key, &pk, pid_tgid);
    tp_info_pid_t *tp_info = find_parent_process_trace(&t_key);

    const u32 len = count & k_log_event_max_log_mask;

    log_event_t *e = (log_event_t *)log_event_mem();
    if (!e) {
        bpf_dbg_printk("logenricher: failed to reserve event space");
        return 0;
    }
    e->tgid = pid_tgid >> 32;
    e->len = len;
    e->pid_tp = tp_info ? *tp_info : (tp_info_pid_t){0};
    e->fd = fd;
    bpf_probe_read_user(e->log, e->len, iov.iov_base);

    if (fd == 0) {
        // We are in the TTY path so we can resolve the filepath
        // from the file struct.
        // NOTE: we could theoretically use the FD similarly to how
        // we do in the pipe case, this approach has less moving parts.
        struct path path = BPF_CORE_READ(iocb, ki_filp, f_path);
        resolve_path((char *)e->file_path, &path, task);
    } else {
        // This is a pipe write, there's no file path to resolve in the
        // file struct, we will write to the process FD directly.
        e->file_path[0] = '\0';
    }

    const long eagain = -11;
    u8 retries = 3;
    if (len > 0) {
        // From this point on, the responsibility of writing to stdout is on us,
        // so if something fails, we must always fallback to writing the original data.
    retry:
        if (retries == 0) {
            bpf_dbg_printk("logenricher: exceeded max retries writing log event to ringbuf!");
            return 0;
        }
        const long err = bpf_ringbuf_output(&log_events,
                                            e,
                                            (sizeof(log_event_t) + len) & k_log_event_max_size_mask,
                                            log_events_flags());
        if (err == eagain) {
            retries--;
            goto retry;
        }
        if (err < 0) {
            bpf_dbg_printk("logenricher: failed to write log event to ringbuf: %d", err);
            return 0;
        }

        // Delete current buffer to avoid double logging.
        char *zero = bpf_map_lookup_elem(&zeros, &(u32){0});
        if (!zero) {
            bpf_dbg_printk("logenricher: failed to get zero buffer");
            return 0;
        }
        bpf_probe_write_user(iov.iov_base, zero, len);
    }

    return 0;
}

SEC("kprobe/tty_write")
int BPF_KPROBE(obi_kprobe_tty_write, struct kiocb *iocb, struct iov_iter *from) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    struct tty_file_private *tfp =
        (struct tty_file_private *)BPF_CORE_READ(iocb, ki_filp, private_data);
    struct tty_struct *tty = BPF_CORE_READ(tfp, tty);
    bool is_master = tty_driver_is_pty(tty) && tty_driver_is_master(tty);

    struct tty_dev master = {};
    struct tty_dev slave = {};
    if (is_master) {
        struct tty_struct *lnk = BPF_CORE_READ(tty, link);
        tty_dev_fill(&master, tty);
        tty_dev_fill(&slave, lnk);
    } else {
        tty_dev_fill(&slave, tty);
    }

    if (slave.major == 0 && slave.minor == 0) {
        return 0;
    }

    if ((is_master && !(master.termios.c_lflag & k_echo)) && !(slave.termios.c_lflag & k_echo)) {
        return 0;
    }

    return __write(iocb, from, 0, task);
}

SEC("kprobe/pipe_write")
int BPF_KPROBE(obi_kprobe_pipe_write, struct kiocb *iocb, struct iov_iter *from) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    int *fdp = bpf_map_lookup_elem(&pid_fd, &(u64){bpf_get_current_pid_tgid()});
    if (!fdp) {
        return 0;
    }

    return __write(iocb, from, *fdp, task);
}

SEC("kprobe/ksys_write")
int BPF_KPROBE(obi_kprobe_ksys_write, unsigned int fd) {
    (void)ctx;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!pid_tracked(task)) {
        return 0;
    }

    if (bpf_map_update_elem(&pid_fd, &(u64){bpf_get_current_pid_tgid()}, (int *)&fd, BPF_ANY)) {
        bpf_dbg_printk("logenricher: failed to update pid_fd map");
    }

    return 0;
}
