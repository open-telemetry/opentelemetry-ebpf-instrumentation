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
	// maxMembersPerGroup bounds the members of one group kept for one process.
	maxMembersPerGroup = 64
	// maxTopicsPerMember bounds the subscription kept for one member.
	maxTopicsPerMember = 1024

	// kafkaConsumerGroupTTL bounds how long a membership outlives the requests that
	// assert it. Members heartbeat every few seconds (heartbeat.interval.ms 3s, KIP-848
	// server default 5s) and each one refreshes the membership, so only a process that
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

// kafkaMember is one member of a group living in a process. A process may host several
// members of the same group, each with its own subscription: every Kafka Streams thread
// is a consumer of the application's group, and nothing stops an application from
// opening two consumers with the same group.id.
type kafkaMember struct {
	// topics is the member's subscription as far as it was observed: replaced by a fully
	// captured JoinGroup subscription, extended by the topics other requests name.
	topics map[string]struct{}
	// expires is when the member is forgotten unless another membership request renews
	// it. Kept per member: a recycled pid heartbeating for its own group must not keep
	// the previous process' memberships alive.
	expires time.Time
}

func (m *kafkaMember) addTopics(topics []*kafkaparser.GroupTopic, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	for _, topic := range topics {
		name := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		if name == "" {
			continue
		}
		if _, found := m.topics[name]; !found && len(m.topics) >= maxTopicsPerMember {
			continue
		}
		m.topics[name] = struct{}{}
	}
}

// kafkaMembership is what is known about one group a process is a member of.
type kafkaMembership struct {
	// foreign marks a group whose JoinGroup or SyncGroup named a protocol other than
	// "consumer" (Kafka Connect, Schema Registry): it coordinates through the same APIs
	// but is no consumer group. A Heartbeat seen before that JoinGroup leaves it unset.
	foreign bool
	// members are the group's members living in the process, by member id. The group's
	// subscription is the union of theirs.
	members map[string]*kafkaMember
}

func (g *kafkaMembership) member(id string) *kafkaMember {
	m, found := g.members[id]
	if found {
		return m
	}
	if id != "" {
		if pending, found := g.members[""]; found {
			delete(g.members, "")
			g.members[id] = pending
			return pending
		}
	}
	if len(g.members) >= maxMembersPerGroup {
		return nil
	}
	m = &kafkaMember{topics: map[string]struct{}{}}
	g.members[id] = m
	return m
}

// dropExpired forgets the members no request renewed before now.
func (g *kafkaMembership) dropExpired(now time.Time) {
	for id, m := range g.members {
		if !m.expires.After(now) {
			delete(g.members, id)
		}
	}
}

// subscribed reports whether any member of the group subscribes to topic.
func (g *kafkaMembership) subscribed(topic string) bool {
	for _, m := range g.members {
		if _, found := m.topics[topic]; found {
			return true
		}
	}
	return false
}

// kafkaProcessGroups is the membership state of one process, by group id.
type kafkaProcessGroups struct {
	groups map[string]*kafkaMembership
}

// membership returns the state of group, creating it unless the process already holds
// maxGroupsPerProcess memberships (nil then).
func (p *kafkaProcessGroups) membership(group string) *kafkaMembership {
	g, found := p.groups[group]
	if found {
		return g
	}
	if len(p.groups) >= maxGroupsPerProcess {
		return nil
	}
	g = &kafkaMembership{members: map[string]*kafkaMember{}}
	p.groups[group] = g
	return g
}

// dropExpired forgets the members no request renewed before now, and the groups left
// without members.
func (p *kafkaProcessGroups) dropExpired(now time.Time) {
	for group, g := range p.groups {
		g.dropExpired(now)
		if len(g.members) == 0 {
			delete(p.groups, group)
		}
	}
}

// consumerGroup returns the only consumer group the process is a member of, "" when
// there is none or more than one.
func (p *kafkaProcessGroups) consumerGroup() string {
	single := ""
	for group, g := range p.groups {
		if g.foreign {
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
	for candidate, g := range p.groups {
		if g.foreign || !g.subscribed(topic) {
			continue
		}
		if subscribed {
			return "", true
		}
		group, subscribed = candidate, true
	}
	return group, subscribed
}

// KafkaConsumerGroups remembers, per process, the consumer groups it is a member of, the
// members it hosts in each and the subscription of every member. Membership is learned
// from the requests only a member sends (JoinGroup, SyncGroup, Heartbeat,
// ConsumerGroupHeartbeat) and forgotten when the member leaves. OffsetCommit and
// OffsetFetch name a group without proving membership (the admin client sends them for
// any group), so they only add topics to a member already known. A Fetch is attributed
// to the one group subscribed to its topic, else to the one consumer group the process
// is a member of: KIP-227 session fetches carry no topic, a topic UUID may not be
// resolved yet, and Heartbeat and SyncGroup carry no topics at all.
//
// Each member expires ttl after the last request asserting it; a Fetch lookup never
// extends it. A recycled pid inherits the previous process' memberships for at most
// ttl, and its own heartbeats renew only its own members. The LRU ttl on the whole entry
// merely reclaims processes that stopped sending anything.
type KafkaConsumerGroups struct {
	lru *expirable.LRU[KafkaProcess, *kafkaProcessGroups]
	ttl time.Duration
	now func() time.Time
}

func NewKafkaConsumerGroups(size int, ttl time.Duration) *KafkaConsumerGroups {
	return &KafkaConsumerGroups{
		lru: expirable.NewLRU[KafkaProcess, *kafkaProcessGroups](size, nil, ttl),
		ttl: ttl,
		now: time.Now,
	}
}

// memberships returns proc's memberships still in force, nil when there are none. It
// drops the expired ones and the process itself once nothing is left.
func (g *KafkaConsumerGroups) memberships(proc KafkaProcess) *kafkaProcessGroups {
	state, found := g.lru.Get(proc)
	if !found {
		return nil
	}
	state.dropExpired(g.now())
	if len(state.groups) == 0 {
		g.lru.Remove(proc)
		return nil
	}
	return state
}

// Join records that req's member, living in proc, is a member of req's group. A complete
// subscription (req.Subscription) replaces the topics known for that member, so a
// rebalance with a changed subscription drops the old topics; anything else adds to
// them. Topics referenced by UUID are resolved through kafkaTopicUUIDToName and skipped
// when unknown.
func (g *KafkaConsumerGroups) Join(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		state = &kafkaProcessGroups{groups: map[string]*kafkaMembership{}}
	}
	group := state.membership(req.GroupID)
	if group == nil {
		return
	}
	m := group.member(req.MemberID)
	if m == nil {
		return
	}
	m.expires = g.now().Add(g.ttl)
	switch {
	case group.foreign || (req.ProtocolType != "" && req.ProtocolType != kafkaparser.ConsumerProtocolType):
		group.foreign = true
		for _, m := range group.members {
			m.topics = nil // whatever was added while the group passed for a consumer group is dead weight
		}
	case req.Subscription:
		m.topics = map[string]struct{}{}
		m.addTopics(req.Topics, kafkaTopicUUIDToName)
	default:
		m.addTopics(req.Topics, kafkaTopicUUIDToName)
	}
	g.lru.Add(proc, state)
}

// Leave forgets the given members of group in proc (LeaveGroup, or a
// ConsumerGroupHeartbeat with a negative member epoch); the group itself once none is
// left. A LeaveGroup naming members proc does not host, as the admin client sends to
// remove members from any group, changes nothing.
func (g *KafkaConsumerGroups) Leave(proc KafkaProcess, group string, members []string) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		return
	}
	membership, member := state.groups[group]
	if !member {
		return
	}
	for _, id := range members {
		delete(membership.members, id)
	}
	if len(membership.members) > 0 {
		return
	}
	delete(state.groups, group)
	if len(state.groups) == 0 {
		g.lru.Remove(proc)
	}
}

// Enrich adds the topics named by an OffsetCommit or OffsetFetch to the subscription of
// req's member in proc; the request is ignored when proc does not host that member of
// that group (OffsetFetch before v9 names no member). It does not renew the membership:
// these requests are no evidence of it (see Join).
func (g *KafkaConsumerGroups) Enrich(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		return
	}
	group, member := state.groups[req.GroupID]
	if !member || group.foreign {
		return
	}
	m, found := group.members[req.MemberID]
	if !found {
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
	state := g.memberships(proc)
	if state == nil {
		return ""
	}
	if group, subscribed := state.topicGroup(topic); subscribed {
		return group
	}
	return state.consumerGroup()
}
