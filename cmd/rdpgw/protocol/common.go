package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/transport"
)

const (
	headerLen       = 8
	maxFragmentSize = 65536
)

var errIncompleteFrame = errors.New("incomplete frame")

type RedirectFlags struct {
	Clipboard  bool
	Port       bool
	Drive      bool
	Printer    bool
	Pnp        bool
	DisableAll bool
	EnableAll  bool
}

func handleMsgFrame(packet *packetReader) *message {
	var buf []byte
	for {
		data := packet.getPtr()
		if len(buf) == 0 {
			pt, sz, msg, err := readHeader(data)
			if err == nil {
				packet.incrementPtr(int(sz))
				return &message{packetType: int(pt), length: int(sz), msg: msg}
			}
			if !errors.Is(err, errIncompleteFrame) {
				return &message{err: err}
			}
			buf = make([]byte, 0, headerLen+maxFragmentSize)
		}
		needed := headerLen - len(buf)
		if needed <= 0 {
			_, sz, _, err := readHeader(buf)
			if !errors.Is(err, errIncompleteFrame) {
				return &message{err: err}
			}
			needed = int(sz) - len(buf)
		}
		n := min(needed, len(data))
		buf = append(buf, data[:n]...)
		packet.incrementPtr(n)
		pt, sz, msg, err := readHeader(buf)
		if err == nil {
			return &message{packetType: int(pt), length: int(sz), msg: msg}
		}
		if !errors.Is(err, errIncompleteFrame) {
			return &message{err: err}
		}
		if !packet.hasMoreData() {
			if err := packet.read(); err != nil {
				return &message{err: err}
			}
			if !packet.hasMoreData() {
				return &message{err: io.ErrNoProgress}
			}
		}
	}
}

// readMessage parses and defragments a packet from a Transport. It returns
// at most the bytes that have been reported by the packet.
func readMessage(in transport.Transport) ([]*message, error) {
	messages := make([]*message, 0)

	packet := newTransportPacket(in)
	err := packet.read()
	if err != nil {
		return messages, err
	}

	var message *message
	for packet.hasMoreData() {
		message = handleMsgFrame(packet)
		if message.err != nil {
			return messages, message.err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

// createPacket wraps the data into the protocol packet
func createPacket(pktType uint16, data []byte) (packet []byte) {
	size := len(data) + 8
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(pktType))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(buf, binary.LittleEndian, uint32(size))
	buf.Write(data)

	return buf.Bytes()
}

// readHeader parses a packet and verifies its reported size. The wire
// layout is [type:2][reserved:2][size:4][body...] where size counts the
// 8-byte header plus the body. handleMsgFrame caps the reassembled body
// at maxFragmentSize, so any size outside [headerLen, headerLen+maxFragmentSize]
// is invalid and rejected before slicing.
func readHeader(data []byte) (packetType uint16, size uint32, packet []byte, err error) {
	if len(data) < headerLen {
		return 0, 0, nil, errIncompleteFrame
	}
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &packetType)
	r.Seek(4, io.SeekStart)
	binary.Read(r, binary.LittleEndian, &size)
	if size < headerLen || size-headerLen > maxFragmentSize {
		return packetType, size, nil, fmt.Errorf("invalid declared size %d", size)
	}
	if len(data) < int(size) {
		return packetType, size, data[headerLen:], errIncompleteFrame
	}
	return packetType, size, data[headerLen:size], nil
}

// forwards data from a Connection to Transport and wraps it in the rdpgw protocol
func forward(in net.Conn, tunnel *Tunnel) {
	defer in.Close()

	b1 := new(bytes.Buffer)
	buf := make([]byte, 4086)

	for {
		n, err := in.Read(buf)
		if err != nil {
			log.Printf("Error reading from local conn %s", err)
			break
		}
		binary.Write(b1, binary.LittleEndian, uint16(n))
		b1.Write(buf[:n])
		tunnel.Write(createPacket(PKT_TYPE_DATA, b1.Bytes()))
		b1.Reset()
	}
}

// receive data received from the gateway client, unwrap and forward the remote desktop server
func receive(data []byte, out net.Conn) {
	buf := bytes.NewReader(data)

	var cblen uint16
	binary.Read(buf, binary.LittleEndian, &cblen)
	pkt := make([]byte, cblen)
	binary.Read(buf, binary.LittleEndian, &pkt)

	out.Write(pkt)
}

// wrapSyscallError takes an error and a syscall name. If the error is
// a syscall.Errno, it wraps it in a os.SyscallError using the syscall name.
func wrapSyscallError(name string, err error) error {
	if _, ok := err.(syscall.Errno); ok {
		err = os.NewSyscallError(name, err)
	}
	return err
}
