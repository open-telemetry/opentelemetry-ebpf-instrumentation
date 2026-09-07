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
	// maxTopicsPerProcess bounds the per-topic entries kept for one process.
	maxTopicsPerProcess = 1024

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

type kafkaGroupEntry struct {
	group string
	// ambiguous marks a topic consumed by two groups of the same process. Such an entry
	// never resolves to a group again.
	ambiguous bool
}

// learnTopic folds group into current; a different group makes the entry ambiguous.
func learnTopic(current kafkaGroupEntry, group string) kafkaGroupEntry {
	if current.ambiguous || current.group == group {
		return current
	}
	if current.group == "" {
		return kafkaGroupEntry{group: group}
	}
	return kafkaGroupEntry{ambiguous: true}
}

// kafkaProcessGroups is the membership state of one process.
type kafkaProcessGroups struct {
	// groups the process is a member of. The value marks a foreign group: one whose
	// JoinGroup or SyncGroup named a protocol other than "consumer" (Kafka Connect,
	// Schema Registry), which coordinates through the same APIs but is no consumer group.
	// A Heartbeat seen before that JoinGroup adds the group as a (presumed) consumer group.
	groups map[string]bool
	// topics maps each topic the requests named to the group consuming it.
	topics map[string]kafkaGroupEntry
}

func newKafkaProcessGroups() *kafkaProcessGroups {
	return &kafkaProcessGroups{groups: map[string]bool{}, topics: map[string]kafkaGroupEntry{}}
}

// consumerGroup returns the only consumer group the process is a member of, "" when
// there is none or more than one.
func (p *kafkaProcessGroups) consumerGroup() string {
	single := ""
	for group, foreign := range p.groups {
		if foreign {
			continue
		}
		if single != "" {
			return ""
		}
		single = group
	}
	return single
}

func (p *kafkaProcessGroups) learnTopics(topics []*kafkaparser.GroupTopic, group string, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	for _, topic := range topics {
		name := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		if name == "" {
			continue
		}
		current, found := p.topics[name]
		if !found && len(p.topics) >= maxTopicsPerProcess {
			continue
		}
		p.topics[name] = learnTopic(current, group)
	}
}

// forgetGroup drops group and the topic entries attributed to it; ambiguous entries
// stay ambiguous, since the other group consuming the topic is still a member.
func (p *kafkaProcessGroups) forgetGroup(group string) {
	delete(p.groups, group)
	for topic, entry := range p.topics {
		if entry.group == group {
			delete(p.topics, topic)
		}
	}
}

// KafkaConsumerGroups remembers, per process, the consumer groups it is a member of and
// which topic each group consumes. Membership is learned from the requests only a
// member sends (JoinGroup, SyncGroup, Heartbeat, ConsumerGroupHeartbeat) and forgotten
// when the member leaves. OffsetCommit and OffsetFetch name a group without proving
// membership (the admin client sends them for any group), so they only add topics to
// a membership already established. A process member of a single consumer group
// reports it for every Fetch whose topic has no entry: KIP-227 session fetches carry no
// topic, a topic UUID may not be resolved yet, and Heartbeat and SyncGroup carry no
// topics at all.
//
// Entries expire ttl after the last membership request; a Fetch lookup never extends
// them, so a recycled pid cannot keep the previous process' group alive.
type KafkaConsumerGroups struct {
	lru *expirable.LRU[KafkaProcess, *kafkaProcessGroups]
}

func NewKafkaConsumerGroups(size int, ttl time.Duration) *KafkaConsumerGroups {
	return &KafkaConsumerGroups{lru: expirable.NewLRU[KafkaProcess, *kafkaProcessGroups](size, nil, ttl)}
}

// Join records that proc is a member of req's group, and of the topics req names.
// Topics referenced by UUID are resolved through kafkaTopicUUIDToName and skipped when
// unknown.
func (g *KafkaConsumerGroups) Join(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state, found := g.lru.Get(proc)
	if !found {
		state = newKafkaProcessGroups()
	}
	foreign := req.ProtocolType != "" && req.ProtocolType != kafkaparser.ConsumerProtocolType
	state.groups[req.GroupID] = state.groups[req.GroupID] || foreign
	if !foreign {
		state.learnTopics(req.Topics, req.GroupID, kafkaTopicUUIDToName)
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
	state.forgetGroup(group)
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
	if foreign, member := state.groups[req.GroupID]; !member || foreign {
		return
	}
	state.learnTopics(req.Topics, req.GroupID, kafkaTopicUUIDToName)
}

// Lookup returns the group consuming topic in proc. Without a per-topic entry, either
// because the topic is unknown or because its subscription was never seen (Heartbeat
// only after a mid-stream attach, JoinGroup cut by the kernel buffer), it falls back to
// the single consumer group the process is a member of. Empty otherwise.
func (g *KafkaConsumerGroups) Lookup(proc KafkaProcess, topic string) string {
	if g == nil {
		return ""
	}
	state, found := g.lru.Get(proc)
	if !found {
		return ""
	}
	if entry, found := state.topics[topic]; found {
		if entry.ambiguous {
			return ""
		}
		return entry.group
	}
	return state.consumerGroup()
}
