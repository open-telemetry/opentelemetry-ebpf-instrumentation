// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

// QoSLevel represents the Quality of Service level for MQTT messages.
type QoSLevel uint8

const (
	QoSAtMostOnce  QoSLevel = 0 // Fire and forget
	QoSAtLeastOnce QoSLevel = 1 // Acknowledged delivery
	QoSExactlyOnce QoSLevel = 2 // Assured delivery
)
