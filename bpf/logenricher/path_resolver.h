// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Adapted from: https://github.com/elastic/ebpf/blob/main/GPL/Events/PathResolver.h

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <logenricher/types.h>

#include <logenricher/maps/path_resolver_scratch.h>

// Resolve a struct path to a string. Returns a boolean indicating whether the
// path construction errored/was truncated or was successful.
static __always_inline bool
resolve_path(char *buf, struct path *path, const struct task_struct *task) {
    long size = 0;
    bool truncated = true;

    struct fs_struct *fs_struct = BPF_CORE_READ(task, fs);
    struct path root = BPF_CORE_READ(fs_struct, root);
    struct vfsmount *curr_vfsmount = BPF_CORE_READ(path, mnt);

    // All struct vfsmount's are stored in a struct mount. We need fields in
    // the struct mount to continue the dentry walk when we hit the root of a
    // mounted filesystem.
    struct mount *mnt = container_of(curr_vfsmount, struct mount, mnt);
    struct dentry *curr_dentry = BPF_CORE_READ(path, dentry);
    struct dentry **dentry_arr;

    // Ensure we make buf an empty string early up here so if we exit with any
    // sort of error, we won't leave garbage in it if it's uninitialized
    buf[0] = '\0';

    if (!(dentry_arr = bpf_map_lookup_elem(&path_resolver_scratch, &(u32){0}))) {
        bpf_dbg_printk("could not get path resolver scratch area");
        goto out_err;
    }

    // Loop 1, follow the dentry chain (up to a maximum of
    // k_path_resolver_max_components) and store pointers to each dentry in
    // dentry_arr
    for (int i = 0; i < k_path_resolver_max_components; i++) {
        if (BPF_CORE_READ(mnt, mnt_parent) == mnt) {
            // We've reached the mount namespace root if mnt->parent points
            // back to mnt. Fill the rest of the array with NULLs so it's
            // ignored.
            truncated = false;
            dentry_arr[i] = NULL;
            continue;
        }

        if (curr_dentry == root.dentry && curr_vfsmount == root.mnt) {
            // We've reached the global root if both the current dentry and the
            // current vfsmount match those of the root struct path. Fill in
            // the rest of dentry_arr with NULLs so the next loop ignores the
            // remaining entries.
            truncated = false;
            dentry_arr[i] = NULL;
            continue;
        }

        struct dentry *parent = BPF_CORE_READ(curr_dentry, d_parent);
        if (curr_dentry == parent || curr_dentry == BPF_CORE_READ(curr_vfsmount, mnt_root)) {
            // We've hit the root of a mounted filesystem. The dentry walk must
            // be continued from mnt_mountpoint in the current struct mount.
            // Also update curr_vfsmount to point to the parent filesystem root.
            curr_dentry = (struct dentry *)BPF_CORE_READ(mnt, mnt_mountpoint);
            mnt = BPF_CORE_READ(mnt, mnt_parent);
            curr_vfsmount = &mnt->mnt;

            // We might be at another fs root here (in which case
            // curr_dentry->d_name will have "/", we need to go up another
            // level to get an actual component name), so fill the dentry
            // pointer array at this spot with NULL so it's ignored in the next
            // loop and continue to check the above condition again.
            dentry_arr[i] = NULL;
            continue;
        }

        dentry_arr[i] = curr_dentry;
        curr_dentry = parent;
    }

    if (truncated) {
        goto out_err;
    }

    // Loop 2, walk the array of dentry pointers (in reverse order) and
    // copy the d_name component of each one into buf, separating with '/'
    for (int i = k_path_resolver_max_components - 1; i >= 0; i--) {
        struct dentry *dentry = dentry_arr[i];
        if (dentry == NULL) {
            continue;
        }

        struct qstr component = BPF_CORE_READ(dentry, d_name);
        if (size + component.len + 1 > k_pts_file_path_len_max) {
            bpf_dbg_printk("path under construction too long, buf=[%s]", buf);
            goto out_err;
        }

        // Note that even though the value of size is guaranteed to be
        // less than k_pts_file_path_len_max_mask here, we have to apply the bound again
        // before using it an index into an array as if it's spilled to the
        // stack by the compiler, the verifier bounds information will not be
        // retained after each bitwise and (this only carries over when stored
        // in a register).
        buf[size & k_pts_file_path_len_max_mask] = '/';
        size = (size + 1) & k_pts_file_path_len_max_mask;

        int ret =
            bpf_probe_read_str(buf + (size & k_pts_file_path_len_max_mask),
                               k_pts_file_path_len_max > size ? k_pts_file_path_len_max - size : 0,
                               (void *)component.name);

        if (ret > 0) {
            size += ((ret - 1) & k_pts_file_path_len_max_mask);
        } else {
            bpf_dbg_printk("could not read d_name at: %p, current path=[%s]", component.name, buf);
            goto out_err;
        }
    }

    // Special case: root directory. If the path is "/", the above loop will
    // not have run and thus path_string will be an empty string. We handle
    // that case here.
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
    }

    return true;

out_err:
    buf[0] = '\0';
    return false;
}
