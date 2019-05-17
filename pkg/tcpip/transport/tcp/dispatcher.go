// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"math/rand"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type segmentEndpoint struct {
	segmentEndpointEntry
	s  *segment
	ep *endpoint
}

// processor is responsible for dispatching packets to a
type processor struct {
	segmentEndpointQueue segmentEndpointQueue `state:"wait"`
	newSegmentWaker      sleep.Waker          `state:"manual"`
	id                   int
}

func newProcessor(id int, queueLen int) *processor {
	p := &processor{id: id}
	p.segmentEndpointQueue.setLimit(queueLen)
	go p.handleSegments()
	return p
}

func (p *processor) queuePacket(s *segment, ep *endpoint) {
	// Send packet to worker goroutine.
	if p.segmentEndpointQueue.enqueue(&segmentEndpoint{s: s, ep: ep}) {
		p.newSegmentWaker.Assert()
	} else {
		// The queue is full, so we drop the segment.
		ep.stack.Stats().DroppedPackets.Increment()
		s.decRef()
	}
}

func (p *processor) handleSegments() {
	const newSegmentWaker = 1
	s := sleep.Sleeper{}
	s.AddWaker(&p.newSegmentWaker, newSegmentWaker)
	epMap := make(map[stack.TransportEndpointID]*endpoint, maxSegmentsPerWake)
	defer s.Done()
	for {
		s.Fetch(true)
		// We process in batches of 100 so that we send timely
		// acks.
		for i := 0; i < maxSegmentsPerWake; i++ {
			sep := p.segmentEndpointQueue.dequeue()
			if sep == nil {
				break
			}
			if !sep.ep.segmentQueue.enqueue(sep.s) {
				sep.ep.stack.Stats().DroppedPackets.Increment()
				sep.s.decRef()
				continue
			}
			if _, ok := epMap[sep.ep.id]; !ok {
				epMap[sep.ep.id] = sep.ep
			}
		}
		for id, ep := range epMap {
			delete(epMap, id)
			ep.mu.RLock()
			epState := ep.state
			workerRunning := ep.workerRunning
			ep.mu.RUnlock()
			// For listening sockets and sockets for which the
			// worker has not yet been started do not bypass
			// normal segment handling.
			if !epState.connected() || !workerRunning {
				ep.newSegmentWaker.Assert()
				continue
			}
			// If the endpoint is in a connected state then we do
			// direct delivery to ensure low latency and avoid
			// scheduler interactions.
			if !ep.workMu.TryLock() {
				ep.newSegmentWaker.Assert()
				continue
			}
			ep.handleSegments()
			ep.workMu.Unlock()
		}
		if !p.segmentEndpointQueue.empty() {
			p.newSegmentWaker.Assert()
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. Each processor has a segment queue that
// contains the segment and the endpoint id in each entry. The queue is selected
// based on the hash of the endpoint id to ensure that delivery for the same
// endpoint happens in-order.
type dispatcher struct {
	processors []*processor
	seed       uint32
}

const processorQueueLen = 10000

func newDispatcher(nProcessors int) *dispatcher {
	processors := []*processor{}
	for i := 0; i < nProcessors; i++ {
		processors = append(processors, newProcessor(i, processorQueueLen))
	}
	return &dispatcher{
		processors: processors,
		seed:       rand.Uint32(),
	}
}

var loopbackSubnet = func() tcpip.Subnet {
	sn, err := tcpip.NewSubnet("\x7f\x00\x00\x00", "\xff\x00\x00\x00")
	if err != nil {
		panic(err)
	}
	return sn
}()

func isLoopbackAddress(addr tcpip.Address) bool {
	const ipv6Loopback = tcpip.Address("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	if loopbackSubnet.Contains(addr) || addr == ipv6Loopback {
		return true
	}
	return false
}

func (d *dispatcher) queuePacket(r *stack.Route, stackEP stack.TransportEndpoint, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	ep := stackEP.(*endpoint)
	s := newSegment(r, id, vv)
	if !s.parse() {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		s.decRef()
		return
	}

	if !s.csumValid {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	p := d.selectProcessor(id)
	p.queuePacket(s, ep)
	return
}

// reciprocalScale scales a value into range [0, n).
//
// This is similar to val % n, but faster.
// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
func reciprocalScale(val, n uint32) uint32 {
	return uint32((uint64(val) * uint64(n)) >> 32)
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8),
	}

	h := jenkins.Sum32(d.seed)
	h.Write(payload)
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))
	hash := h.Sum32()

	idx := reciprocalScale(hash, uint32(len(d.processors)))
	return d.processors[idx]
}
