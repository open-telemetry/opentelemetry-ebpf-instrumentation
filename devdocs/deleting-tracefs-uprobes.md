# Deleting `tracefs` probes when they stick around

Without `uprobe_multi` and `CAP_SYS_ADMIN` on a kernel that has [CVE-2025-38466](https://app.opencve.io/cve/CVE-2025-38466)
patched, we cannot use the PMU for uprobes and we fall back on tracefs. Kprobes fall back on tracefs too when PMU
access is denied, for example with `kernel.perf_event_paranoid` above 2. Tracefs probes need to be explicitly cleaned
up and we have proper closer path for it. However, in case OBI crashes or is killed (especially while development),
you may end up with a number of stale/ghost `tracefs` probes that you may want to manually clean up.

Kernel livepatches can introduce multiple copies of a probed function. The PMU reports `EADDRNOTAVAIL`
for an ambiguous name. When PMU access is denied, tracefs can report `EINVAL` for the same name.
OBI checks `/proc/kallsyms` for duplicates before trying a syscall prefix. It attaches to each resolvable
copy through tracefs using module-qualified names where possible. Disambiguating the original kernel function or multiple
copies within one module requires visible kernel addresses. OBI logs partial coverage and retries missing
targets every 30 seconds. It also checks `/sys/kernel/livepatch` for same-named replacements of probes
attached before a patch was applied. Both probe copies can fire for one operation.

Here's how you can check if you have any stale leftover probes:

```sh
sudo grep -E '^[pr][0-9]*:obi_' /sys/kernel/tracing/uprobe_events /sys/kernel/tracing/kprobe_events
```

If tracefs is not mounted at `/sys/kernel/tracing`, use `/sys/kernel/debug/tracing` instead.

Here's a script that will clean up stale `tracefs` probes. It is safe to run while OBI is running: the kernel refuses
to delete probes that are still in use, and the script reports them as kept.

```sh
sudo sh <<'SCRIPT'
T=/sys/kernel/tracing
[ -e "$T/uprobe_events" ] || T=/sys/kernel/debug/tracing

for f in "$T/uprobe_events" "$T/kprobe_events"; do
  [ -e "$f" ] || continue

  for group in $(sed -n 's|^[pr][0-9]*:\(obi_[[:alnum:]_]*\)/.*|\1|p' "$f" | sort -u); do
    if printf '%s\n' "-:$group/" 2>/dev/null >> "$f"; then
      echo "removed $group"
      continue
    fi

    # kernels without group deletion, or a group still in use: delete event by event
    kept=0
    for event in $(sed -n "s|^[pr][0-9]*:$group/\([^ ]*\) .*|\1|p" "$f"); do
      printf '%s\n' "-:$group/$event" 2>/dev/null >> "$f" || kept=$((kept + 1))
    done

    if [ "$kept" -eq 0 ]; then
      echo "removed $group"
    else
      echo "kept $group: probes in use by a running OBI ($kept)"
    fi
  done
done
SCRIPT
```
