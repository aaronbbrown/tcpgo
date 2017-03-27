package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	ArpRequest = 1
	ArpReply   = 2

	ArpHwTypeEthernet = 0x0001
)

var (
	req  ifReq
	fTun *os.File
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

type arpHdr struct {
	HwType  uint16
	ProType uint16
	HwSize  uint8
	ProSize uint8
	OpCode  uint16
	Data    []byte
}

type arpIpv4 struct {
	SMAC net.HardwareAddr
	SIP  net.IP
	DMAC net.HardwareAddr
	DIP  net.IP
}

func (eth *EthHdr) String() string {
	return fmt.Sprintf("[ETHERNET] Src: %s, Dst: %s, EtherType: %x, Payload: %v",
		eth.SrcAddr,
		eth.DstAddr,
		eth.EtherType,
		bytes.Trim(eth.Payload, "\x00"))
}

func (eth *EthHdr) Copy() *EthHdr {
	eth2 := &EthHdr{DstAddr: make(net.HardwareAddr, 6),
		SrcAddr:   make(net.HardwareAddr, 6),
		EtherType: eth.EtherType,
		Payload:   make([]byte, len(eth.Payload))}

	copy(eth2.DstAddr, eth.DstAddr)
	copy(eth2.SrcAddr, eth.SrcAddr)

	return eth2
}

func (eth *EthHdr) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, eth.DstAddr)
	binary.Write(buf, binary.BigEndian, eth.SrcAddr)
	binary.Write(buf, binary.BigEndian, eth.EtherType)
	buf.Write(eth.Payload)
	return buf.Bytes()
}

func (arp *arpHdr) String() string {
	return fmt.Sprintf("[ARP HEADER] HwType: %x, ProType: %x, HwSize: %d, ProSize: %d, OpCode: %x, Data: %v",
		arp.HwType,
		arp.ProType,
		arp.HwSize,
		arp.ProSize,
		arp.OpCode,
		arp.Data)
}

func (a *arpIpv4) String() string {
	return fmt.Sprintf("[ARP IPV4] Source MAC: %s, Destination MAC: %s, Source IP: %s, Destination IP: %s",
		a.SMAC,
		a.DMAC,
		a.SIP,
		a.DIP)
}

func (a *arpIpv4) Copy() *arpIpv4 {
	a2 := &arpIpv4{SMAC: make(net.HardwareAddr, 6),
		SIP:  make(net.IP, 4),
		DMAC: make(net.HardwareAddr, 6),
		DIP:  make(net.IP, 4)}

	copy(a2.SMAC, a.SMAC)
	copy(a2.SIP, a.SIP)
	copy(a2.DMAC, a.DMAC)
	copy(a2.DIP, a.DIP)
	return a2
}

func (a *arpIpv4) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, a.SMAC)
	binary.Write(buf, binary.LittleEndian, a.SIP)
	binary.Write(buf, binary.BigEndian, a.DMAC)
	binary.Write(buf, binary.LittleEndian, a.DIP)
	return buf.Bytes()

}

func IpInAddrs(addrs []net.Addr, ip net.IP) bool {
	for _, addr := range addrs {
		addrIp, _, _ := net.ParseCIDR(addr.String())
		if ip.Equal(addrIp) {
			return true
		}
	}
	return false
}

// eth is the original ethHdr
func (arp *arpHdr) Handle(fTun *os.File, eth *EthHdr, netIf *net.Interface) (resp []byte, err error) {
	if arp.HwType != ArpHwTypeEthernet {
		return nil, fmt.Errorf("Unsupported HwType: %x", arp.HwType)
	}

	if arp.ProType != syscall.ETH_P_IP {
		return nil, fmt.Errorf("Unsupported ProType: %x", arp.ProType)
	}

	arpIpv4 := UnmarshalArpIpv4(arp.Data)
	log.Println(arpIpv4)

	// TODO implement ARP translation table cache
	switch arp.OpCode {
	case ArpRequest:
		// is the DIP in my list of IPs for this interface
		addrs, _ := netIf.Addrs()
		if !IpInAddrs(addrs, arpIpv4.DIP) {
			// not for me
			return nil, nil
		}
		replyData := arpIpv4.Copy()
		replyData.SIP, replyData.DIP = arpIpv4.DIP, arpIpv4.SIP
		replyData.SMAC, replyData.DMAC = netIf.HardwareAddr, arpIpv4.SMAC

		reply := arp.Copy()
		reply.OpCode = ArpReply
		reply.Data = replyData.Marshal()

		ethReply := eth.Copy()
		ethReply.SrcAddr, ethReply.DstAddr = netIf.HardwareAddr, eth.SrcAddr
		ethReply.Payload = reply.Marshal()

		fTun.Write(ethReply.Marshal())
		log.Println("[REPLY]", ethReply)

	default:
		return nil, fmt.Errorf("OpCode not implemented: %d", arp.OpCode)
	}

	return nil, nil
}

func (arp *arpHdr) Copy() *arpHdr {
	arp2 := &arpHdr{
		HwType:  arp.HwType,
		ProType: arp.ProType,
		HwSize:  arp.HwSize,
		ProSize: arp.ProSize,
		OpCode:  arp.OpCode,
		Data:    make([]byte, len(arp.Data))}

	copy(arp2.Data, arp.Data)
	return arp2
}

func (arp *arpHdr) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, arp.HwType)
	binary.Write(buf, binary.BigEndian, arp.ProType)
	binary.Write(buf, binary.BigEndian, arp.HwSize)
	binary.Write(buf, binary.BigEndian, arp.ProSize)
	binary.Write(buf, binary.BigEndian, arp.OpCode)
	buf.Write(arp.Data)
	return buf.Bytes()
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

// read a uint16 from a reader
func ReadUint16(r io.Reader) (uint16, error) {
	buf := make([]byte, 2)
	_, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

func IntToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result
}

func UnmarshalArpHdr(data []byte) *arpHdr {
	return &arpHdr{
		HwType:  binary.BigEndian.Uint16(data[0:2]),
		ProType: binary.BigEndian.Uint16(data[2:4]),
		HwSize:  uint8(data[4:5][0]),
		ProSize: uint8(data[5:6][0]),
		OpCode:  binary.BigEndian.Uint16(data[6:8]),
		Data:    bytes.TrimRight(data[8:], "\x00")}
}

func UnmarshalArpIpv4(data []byte) *arpIpv4 {
	return &arpIpv4{
		SMAC: net.HardwareAddr(data[0:6]),
		// Not sure why IPs are LittleEndian
		SIP:  IntToIP(binary.LittleEndian.Uint32(data[6:10])),
		DMAC: net.HardwareAddr(data[10:16]),
		DIP:  IntToIP(binary.LittleEndian.Uint32(data[16:20]))}
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

	et, err := ReadUint16(r)
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

func tapAlloc(f *os.File) (string, error) {
	req.Flags = syscall.IFF_TAP | syscall.IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return "", error(errno)
	}
	return string(bytes.Trim(req.Name[:], "\x00")), nil
}

func ifUp(dev string) error {
	err := exec.Command("ip", "addr", "add", "10.1.2.3", "dev", dev).Run()
	if err != nil {
		return err
	}

	return exec.Command("ip", "link", "set", dev, "up").Run()
}

func main() {
	fTun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatal("Could not open tun device: ", err)
	}
	defer fTun.Close()

	dev, err := tapAlloc(fTun)
	if err != nil {
		log.Fatal("Could not allocate TAP: ", err)
	}

	netIf, err := net.InterfaceByName(dev)
	if err != nil {
		log.Fatal("Could not get interface details: ", err)
	}

	log.Printf("Allocated TAP on %s", netIf)

	if err := ifUp(netIf.Name); err != nil {
		log.Fatal("Error configuring TAP interface: ", err)
	}

	r := bufio.NewReader(fTun)

	for {
		eth, err := UnmarshalEthHdr(r)
		if err != nil {
			log.Fatal("Unable to unmarshal Ethernet Header: ", err)
		}

		log.Println(eth)
		switch eth.EtherType {
		case syscall.ETH_P_ARP:
			arp := UnmarshalArpHdr(eth.Payload)
			log.Println(arp)
			resp, err := arp.Handle(fTun, eth, netIf)
			if err != nil {
				log.Printf("Error handling ARP packet: %v", err)
			}
			if resp == nil {
				continue
			}

		default:
			log.Printf("Unhandled EtherType: %x", eth.EtherType)
		}
	}
}
