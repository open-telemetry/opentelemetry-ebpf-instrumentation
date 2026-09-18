# Deleting `tracefs` uprobes when they stick around

Without `uprobe_multi` and `CAP_SYS_ADMIN` on a kernel that has [CVE-2025-38466](https://app.opencve.io/cve/CVE-2025-38466)
patched, we cannot use the PMU for uprobes and we fall back on tracefs. Tracefs needs to be explicitly cleaned up and we
have proper closer path for it. However, in case OBI crashes (especially while development), you may end up with a number of
stale/ghost `tracefs` probes that you may want to manually clean up.

Here's how you can check if you have any stale leftover probes:

```sh
sudo grep 'obi_' /sys/kernel/debug/tracing/uprobe_events
```

Here's a script that will clean up stale `tracefs` probes:

```sh
cleanup_list=$(mktemp)

sudo awk '$1 ~ /^[pr]:obi_[[:xdigit:]]+\// {
  event=$1
  sub(/^[pr]:/, "-:", event)
  print event
}' /sys/kernel/debug/tracing/uprobe_events > "$cleanup_list"

while IFS= read -r command; do
  sudo sh -c 'printf "%s\n" "$1" >> /sys/kernel/debug/tracing/uprobe_events' sh "$command"
done < "$cleanup_list"

rm "$cleanup_list"
```