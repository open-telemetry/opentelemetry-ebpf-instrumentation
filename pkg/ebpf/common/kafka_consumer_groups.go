// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
)

const (
	// maxGroupsPerProcess bounds the memberships kept for one process.
	maxGroupsPerProcess = 64
	// maxTopicsPerGroup bounds the subscription kept for one membership.
	maxTopicsPerGroup = 1024

	// kafkaConsumerGroupTTL bounds how long a membership outlives the requests that
	// assert it. Members heartbeat every few seconds (heartbeat.interval.ms 3s, KIP-848
	// server default 5s) and each one refreshes the entry, so only a process that
	// stopped talking to the coordinator, typically because it exited and its pid may
	// be reused, expires. Well above session.timeout.ms (45s) so a stalled but live
	// member is not forgotten before the broker forgets it. A constant on purpose: a
	// deployment raising heartbeat.interval.ms above it loses the attribute between
	// heartbeats rather than keeping stale pids around longer.
	kafkaConsumerGroupTTL = 2 * time.Minute
)

// KafkaProcess identifies the instrumented process a Kafka request was captured from.
// Fetch requests carry no consumer group, and the group-coordination requests that do
// go to the group coordinator, usually not the leader of the fetched partitions: on a
// dedicated connection (Java, kafka-python) or on that broker's shared connection
// (librdkafka). Either way the process is the only key shared by both.
type KafkaProcess struct {
	Ns  uint32
	Pid uint32
}

// kafkaMembership is what is known about one group a process is a member of.
type kafkaMembership struct {
	// foreign marks a group whose JoinGroup or SyncGroup named a protocol other than
	// "consumer" (Kafka Connect, Schema Registry): it coordinates through the same APIs
	// but is no consumer group. A Heartbeat seen before that JoinGroup leaves it unset.
	foreign bool
	// topics is the group's subscription as far as it was observed: replaced by a fully
	// captured JoinGroup subscription, extended by the topics other requests name.
	topics map[string]struct{}
}

func (m *kafkaMembership) addTopics(topics []*kafkaparser.GroupTopic, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	for _, topic := range topics {
		name := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		if name == "" {
			continue
		}
		if _, found := m.topics[name]; !found && len(m.topics) >= maxTopicsPerGroup {
			continue
		}
		m.topics[name] = struct{}{}
	}
}

// kafkaProcessGroups is the membership state of one process, by group id.
type kafkaProcessGroups struct {
	groups map[string]*kafkaMembership
}

// membership returns the state of group, creating it unless the process already holds
// maxGroupsPerProcess memberships (nil then).
func (p *kafkaProcessGroups) membership(group string) *kafkaMembership {
	m, found := p.groups[group]
	if found {
		return m
	}
	if len(p.groups) >= maxGroupsPerProcess {
		return nil
	}
	m = &kafkaMembership{topics: map[string]struct{}{}}
	p.groups[group] = m
	return m
}

// consumerGroup returns the only consumer group the process is a member of, "" when
// there is none or more than one.
func (p *kafkaProcessGroups) consumerGroup() string {
	single := ""
	for group, m := range p.groups {
		if m.foreign {
			continue
		}
		if single != "" {
			return ""
		}
		single = group
	}
	return single
}

// topicGroup returns the consumer group whose subscription holds topic. subscribed is
// false when no group does; group is "" when more than one does.
func (p *kafkaProcessGroups) topicGroup(topic string) (group string, subscribed bool) {
	for candidate, m := range p.groups {
		if m.foreign {
			continue
		}
		if _, found := m.topics[topic]; !found {
			continue
		}
		if subscribed {
			return "", true
		}
		group, subscribed = candidate, true
	}
	return group, subscribed
}

// KafkaConsumerGroups remembers, per process, the consumer groups it is a member of and
// the subscription of each. Membership is learned from the requests only a member
// sends (JoinGroup, SyncGroup, Heartbeat, ConsumerGroupHeartbeat) and forgotten when
// the member leaves. OffsetCommit and OffsetFetch name a group without proving
// membership (the admin client sends them for any group), so they only add topics to
// a membership already established. A Fetch is attributed to the one group subscribed
// to its topic, else to the one consumer group the process is a member of: KIP-227
// session fetches carry no topic, a topic UUID may not be resolved yet, and Heartbeat
// and SyncGroup carry no topics at all.
//
// Entries expire ttl after the last membership request; a Fetch lookup never extends
// them, so a recycled pid cannot keep the previous process' group alive.
type KafkaConsumerGroups struct {
	lru *expirable.LRU[KafkaProcess, *kafkaProcessGroups]
}

func NewKafkaConsumerGroups(size int, ttl time.Duration) *KafkaConsumerGroups {
	return &KafkaConsumerGroups{lru: expirable.NewLRU[KafkaProcess, *kafkaProcessGroups](size, nil, ttl)}
}

// Join records that proc is a member of req's group. A complete subscription
// (req.Subscription) replaces the topics known for that group, so a rebalance with a
// changed subscription drops the old topics; anything else adds to them. Topics
// referenced by UUID are resolved through kafkaTopicUUIDToName and skipped when unknown.
func (g *KafkaConsumerGroups) Join(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state, found := g.lru.Get(proc)
	if !found {
		state = &kafkaProcessGroups{groups: map[string]*kafkaMembership{}}
	}
	m := state.membership(req.GroupID)
	if m == nil {
		return
	}
	switch {
	case m.foreign || (req.ProtocolType != "" && req.ProtocolType != kafkaparser.ConsumerProtocolType):
		m.foreign = true
		m.topics = nil // whatever was added while the group passed for a consumer group is dead weight
	case req.Subscription:
		m.topics = map[string]struct{}{}
		m.addTopics(req.Topics, kafkaTopicUUIDToName)
	default:
		m.addTopics(req.Topics, kafkaTopicUUIDToName)
	}
	g.lru.Add(proc, state) // also on an existing entry: every membership request renews the ttl
}

// Leave forgets proc's membership in group (LeaveGroup, or a ConsumerGroupHeartbeat
// with a negative member epoch). A LeaveGroup naming a group proc never joined, as the
// admin client sends to remove members, changes nothing. The admin client removing
// members of a group proc itself belongs to is indistinguishable from proc leaving
// (member ids are not tracked): the membership is forgotten and re-learned by the next
// Heartbeat, a few seconds later.
func (g *KafkaConsumerGroups) Leave(proc KafkaProcess, group string) {
	if g == nil {
		return
	}
	state, found := g.lru.Get(proc)
	if !found {
		return
	}
	if _, member := state.groups[group]; !member {
		return
	}
	delete(state.groups, group)
	if len(state.groups) == 0 {
		g.lru.Remove(proc)
	}
}

// Enrich adds the topics named by an OffsetCommit or OffsetFetch to proc's membership
// in req's group; the request is ignored when proc is not a member of that group.
func (g *KafkaConsumerGroups) Enrich(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state, found := g.lru.Get(proc)
	if !found {
		return
	}
	m, member := state.groups[req.GroupID]
	if !member || m.foreign {
		return
	}
	m.addTopics(req.Topics, kafkaTopicUUIDToName)
}

// Lookup returns the group consuming topic in proc: the one group subscribed to it,
// or, when no subscription names it (unknown topic, Heartbeat only after a mid-stream
// attach, JoinGroup cut by the kernel buffer), the single consumer group the process is
// a member of. Empty when several groups qualify or none does.
func (g *KafkaConsumerGroups) Lookup(proc KafkaProcess, topic string) string {
	if g == nil {
		return ""
	}
	state, found := g.lru.Get(proc)
	if !found {
		return ""
	}
	if group, subscribed := state.topicGroup(topic); subscribed {
		return group
	}
	return state.consumerGroup()
}
