// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

public class JavaHelper {
	public static void waitForInspection() {
		try {
			Thread.sleep(Long.getLong("obi.research.wait", 0L));
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

    public static String message() {
        return "java helper";
    }
}
