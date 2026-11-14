// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
)

// javaInjectionQueueLen bounds how many discovered JVMs can wait for injection.
// The queue only fills while an attach is stuck, and a dropped target loses Java
// TLS telemetry for that process, nothing else.
const javaInjectionQueueLen = 100

const javaAttachMaxAttempts = 3

var javaAttachRetryBackoff = 2 * time.Second

func newJavaInjectionQueue(
	log *slog.Logger,
	slot injectionSlot,
	inject func(context.Context, javaagent.InjectionTarget) error,
) *injectionQueue[javaagent.InjectionTarget] {
	return newInjectionQueue(log, "java", slot, javaInjectionQueueLen,
		func(ctx context.Context, target javaagent.InjectionTarget) {
			backoff := javaAttachRetryBackoff
			var err error
			for attempt := 1; attempt <= javaAttachMaxAttempts; attempt++ {
				err = inject(ctx, target)
				if err == nil || ctx.Err() != nil {
					return
				}
				if attempt == javaAttachMaxAttempts {
					break
				}
				log.Debug("retrying java agent attach after failure",
					"pid", target.Pid, "attempt", attempt, "backoff", backoff, "error", err)
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				backoff *= 2
			}
			if err != nil {
				log.Warn("unable to attach java agent to process, Java TLS telemetry will not work",
					"pid", target.Pid, "attempts", javaAttachMaxAttempts, "error", err)
			}
		},
		func(target javaagent.InjectionTarget) bool {
			return target.Type == svc.InstrumentableJava
		})
}
