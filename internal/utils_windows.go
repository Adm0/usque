//go:build windows

package internal

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                            = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid     = iphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procInitializeUnicastIpAddressEntry = iphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procGetIpInterfaceEntry             = iphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry             = iphlpapi.NewProc("SetIpInterfaceEntry")
)

func SyscallCode(proc uintptr, args ...uintptr) error {
	code, _, err := syscall.SyscallN(proc, args...)
	if code != 0 {
		return syscall.Errno(code)
	}
	if err != 0 {
		return err
	}
	return nil
}

func AliasToLuid(alias string) uint64 {
	var luid uint64 = 0
	err := SyscallCode(procConvertInterfaceAliasToLuid.Addr(), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(alias))), uintptr(unsafe.Pointer(&luid)))
	if err != nil {
		fmt.Printf("failed get interface luid: %v", err)
	}
	return luid
}

func AddIpAddress(luid uint64, ip net.IP, mask net.IPMask) error {
	var address = MibUnicastIpAddressRow{}
	syscall.SyscallN(procInitializeUnicastIpAddressEntry.Addr(), uintptr(unsafe.Pointer(&address)))
	address.Address.FromIP(ip)
	bits, _ := mask.Size()
	address.OnLinkPrefixLength = uint8(bits)
	address.InterfaceLuid = luid
	address.DadState = IpDadStatePreferred

	return SyscallCode(procCreateUnicastIpAddressEntry.Addr(), uintptr(unsafe.Pointer(&address)))
}

func SetMTU(luid uint64, family int, mtu int) error {
	entry := &MibIpInterfaceRow{}
	entry.Family = uint16(family)
	entry.InterfaceLuid = luid
	err := SyscallCode(procGetIpInterfaceEntry.Addr(), uintptr(unsafe.Pointer(entry)))
	if err != nil {
		return err
	}
	if entry.Family == syscall.AF_INET {
		entry.SitePrefixLength = 0
	}
	entry.NlMtu = uint32(mtu)
	err = SyscallCode(procSetIpInterfaceEntry.Addr(), uintptr(unsafe.Pointer(entry)))
	if err != nil {
		return err
	}
	return nil
}
