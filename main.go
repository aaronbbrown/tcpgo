package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)
import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

// The EthHdr struct is a wrapper for the ether_header struct in <net/ethernet.h>.
type EthHdr struct {
	DstAddr   net.HardwareAddr // the receiver's MAC address
	SrcAddr   net.HardwareAddr // the sender's MAC address
	EtherType uint16           // packet type ID field
	Payload   []byte
}

func (eth *EthHdr) String() string {
	return fmt.Sprintf("Src: %s, Dst: %s, EtherType: %x, Payload: %v", eth.SrcAddr, eth.DstAddr, eth.EtherType, bytes.Trim(eth.Payload, "\x00"))
}

// Read 6 bytes from an io.Reader and return a MAC addr
func ReadMAC(r io.Reader) (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	return net.HardwareAddr(buf), nil
}

func ReadEtherType(r io.Reader) (uint16, error) {
	buf := make([]byte, 2)
	_, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

func UnmarshalEthHdr(r io.Reader) (*EthHdr, error) {
	eth := &EthHdr{}

	// read dest MAC
	hw, err := ReadMAC(r)
	if err != nil {
		return nil, err
	}
	eth.DstAddr = hw

	// read source MAC
	hw, err = ReadMAC(r)
	if err != nil {
		return nil, err
	}
	eth.SrcAddr = hw

	et, err := ReadEtherType(r)
	if err != nil {
		return nil, err
	}
	eth.EtherType = et

	var payload []byte
	if et >= 1536 {
		// just read it out for now up to jumbo frame size
		payload = make([]byte, 9000)
	} else {
		payload = make([]byte, et)
	}

	// read the payload in
	_, err = r.Read(payload)
	if err != nil {
		return nil, err
	}
	eth.Payload = payload

	return eth, nil
}

func tapAlloc(f *os.File) error {
	req.Flags = syscall.IFF_TAP | syscall.IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return error(errno)
	}
	fmt.Println(string(req.Name[:]))

	return nil
}

var (
	req  ifReq
	fTun *os.File
)

func main() {
	fTun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatal("Could not open tun device: ", err)
	}
	defer fTun.Close()

	if err := tapAlloc(fTun); err != nil {
		log.Fatal("Could not allocate TAP: ", err)
	}

	r := bufio.NewReader(fTun)
	for {
		eth, err := UnmarshalEthHdr(r)
		if err != nil {
			log.Fatal("Unable to unmarshal Ethernet Header: ", err)
		}
		log.Println(eth)
	}

}
