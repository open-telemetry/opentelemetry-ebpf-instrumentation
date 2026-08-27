#!/substsh
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# V crosses a $() pipe held open 400ms after writing: a buggy enricher grabs
# it, and V comes back empty or the loop hangs
i=0
while true; do
    i=$((i + 1))
    V=$(echo "v$i"; sleep 0.4)
    echo "subst i=$i V=$V"
    sleep 0.1
done
