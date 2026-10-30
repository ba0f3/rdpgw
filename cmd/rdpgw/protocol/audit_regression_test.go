package protocol

import (
	"encoding/binary"
	"testing"
)

func TestInvalidDeclaredFrameStopsReading(t *testing.T) {
	for _, size := range []uint32{0, 7, headerLen + maxFragmentSize + 1} {
		frame := make([]byte, headerLen)
		binary.LittleEndian.PutUint32(frame[4:], size)
		in := newTransportMock()
		pkt := newPacketMock()
		pkt.addBytes(frame)
		in.addPacket(pkt)
		messages, err := readMessage(in)
		if err == nil || len(messages) != 0 || in.packetPtr != 1 {
			t.Fatalf("size %d: messages=%d err=%v transport reads=%d", size, len(messages), err, in.packetPtr)
		}
	}
}

func TestOversizedInvalidFrameTerminates(t *testing.T) {
	frame := make([]byte, maxFragmentSize+1)
	binary.LittleEndian.PutUint32(frame[4:], 0)
	in := newTransportMock()
	pkt := newPacketMock()
	pkt.addBytes(frame)
	in.addPacket(pkt)
	if msgs, err := readMessage(in); err == nil || len(msgs) != 0 {
		t.Fatalf("oversized invalid input: messages=%d error=%v", len(msgs), err)
	}
}
