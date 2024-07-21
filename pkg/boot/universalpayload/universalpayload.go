// Copyright 2024 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package universalpayload supports to load FIT (Flat Image Tree) image.
// FIT is a common Payload image format to faciliate the loading process,
// and defined in UniversalPayload Specification.
// More Details about UniversalPayload Specification, please refer:
// https://github.com/universalpayload/spec
package universalpayload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	guid "github.com/google/uuid"
	"github.com/u-root/u-root/pkg/acpi"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/kexec"
	"github.com/u-root/u-root/pkg/smbios"
)

const (
	UniversalPayloadSerialPortInfoGUID       = "0d197eaa-21be-0944-8e67-a2cd0f61e170"
	UniversalPayloadSerialPortInfoRevision   = 1
	UniversalPayloadSerialPortRegisterStride = 1
	UniversalPayloadSerialPortBaudRate       = 115200
	UniversalPayloadSerialPortRegisterBase   = 0x3f8
)

const (
	UniversalPayloadBaseGUID = "1dc6d403-1327-c54e-a1cc-883be9dc18e5"
)

const (
	UniversalPayloadAcpiTableGUID     = "06959a9f-9755-1545-bab6-8bcde784ba87"
	UniversalPayloadAcpiTableRevision = 1
)

const (
	UniversalPayloadSmbiosTableGUID     = "260d0a59-e506-204d-8a82-59ea1b34982d"
	UniversalPayloadSmbiosTableRevision = 1
)

type UniversalPayloadGenericHeader struct {
	Revision uint8
	Reserved uint8
	Length   uint16
}

type UniversalPayloadSerialPortInfo struct {
	Header         UniversalPayloadGenericHeader
	UseMmio        uint8
	RegisterStride uint8
	BaudRate       uint32
	RegisterBase   EfiPhysicalAddress
}

// Structure member 'Pad' is introduced to match the offset of 'Entry'
// in structure UNIVERSAL_PAYLOAD_BASE which is defined in EDK2 UPL.
type UniversalPayloadBase struct {
	Header UniversalPayloadGenericHeader
	Pad    [4]byte
	Entry  EfiPhysicalAddress
}

type UniversalPayloadAcpiTable struct {
	Header UniversalPayloadGenericHeader
	Rsdp   EfiPhysicalAddress
}

type UniversalPayloadSmbiosTable struct {
	Header           UniversalPayloadGenericHeader
	SmBiosEntryPoint EfiPhysicalAddress
}

// Map GUID string to size of corresponding structure. Use
// this map to simplify the length calculation in function
// constructGUIDHob.
var (
	guidToLength = map[string]uintptr{
		UniversalPayloadSerialPortInfoGUID: unsafe.Sizeof(UniversalPayloadSerialPortInfo{}),
		UniversalPayloadBaseGUID:           unsafe.Sizeof(UniversalPayloadBase{}),
		UniversalPayloadAcpiTableGUID:      unsafe.Sizeof(UniversalPayloadAcpiTable{}),
		UniversalPayloadSmbiosTableGUID:    unsafe.Sizeof(UniversalPayloadSmbiosTable{}),
	}
)

// Create GUID Hob with specified GUID string
func constructGUIDHob(name string) (*EfiHobGUIDType, error) {
	length := uint16(unsafe.Sizeof(EfiHobGUIDType{}) + guidToLength[name])

	id, err := guid.Parse(name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse guid:%s", name)
	}

	return &EfiHobGUIDType{
		Header: EfiHobGenericHeader{
			HobType:   EfiHobTypeGUIDExtension,
			HobLength: length,
		},
		Name: id,
	}, nil
}

func constructSerialPortHob() *UniversalPayloadSerialPortInfo {
	// Construct Serial Port Hob
	return &UniversalPayloadSerialPortInfo{
		Header: UniversalPayloadGenericHeader{
			Revision: UniversalPayloadSerialPortInfoRevision,
			Length:   uint16(unsafe.Sizeof(UniversalPayloadSerialPortInfo{})),
		},
		UseMmio:        0,
		RegisterStride: UniversalPayloadSerialPortRegisterStride,
		BaudRate:       UniversalPayloadSerialPortBaudRate,
		RegisterBase:   UniversalPayloadSerialPortRegisterBase,
	}
}

func constructUnivesralPayloadBase(addr uint64) *UniversalPayloadBase {
	return &UniversalPayloadBase{
		Header: UniversalPayloadGenericHeader{
			Revision: 0,
			Length:   uint16(unsafe.Sizeof(UniversalPayloadBase{})),
		},
		Entry: EfiPhysicalAddress(addr),
	}
}

func constructRSDPTable() (*UniversalPayloadAcpiTable, error) {
	rsdp, err := acpi.GetRSDP()
	if err != nil {
		return nil, fmt.Errorf("failed to get rdsp table")
	}

	return &UniversalPayloadAcpiTable{
		Header: UniversalPayloadGenericHeader{
			Revision: UniversalPayloadAcpiTableRevision,
			Length:   uint16(unsafe.Sizeof(UniversalPayloadAcpiTable{})),
		},
		Rsdp: EfiPhysicalAddress(rsdp.RSDPAddr()),
	}, nil
}

func constructSmbiosTable() (*UniversalPayloadSmbiosTable, error) {
	smbiosTableBase, _, err := smbios.SMBIOSBase()
	if err != nil {
		return nil, fmt.Errorf("failed to get smbios base")
	}

	return &UniversalPayloadSmbiosTable{
		Header: UniversalPayloadGenericHeader{
			Revision: UniversalPayloadSmbiosTableRevision,
			Length:   uint16(unsafe.Sizeof(UniversalPayloadSmbiosTable{})),
		},
		SmBiosEntryPoint: EfiPhysicalAddress(smbiosTableBase),
	}, nil
}

func appendMemMapHob(buf *bytes.Buffer, hobLen *uint64) error {
	// Construct system memory resource Hob
	memMap, err := kexec.MemoryMapFromSysfsMemmap()
	if err != nil {
		return fmt.Errorf("failed to get memory map from sysfs")
	}

	memHob, length := hobFromMemMap(memMap)
	if err := binary.Write(buf, binary.LittleEndian, memHob); err != nil {
		return fmt.Errorf("failed to write memory map to buffer")
	}

	*hobLen += length

	return nil
}

func appendSerialPortHob(buf *bytes.Buffer, hobLen *uint64) error {
	// Construct serial port Hob
	serialPortInfo := constructSerialPortHob()
	serialGUIDHob, err := constructGUIDHob(UniversalPayloadSerialPortInfoGUID)
	if err != nil {
		return err
	}

	length := uint64(unsafe.Sizeof(EfiHobGUIDType{}) + unsafe.Sizeof(UniversalPayloadSerialPortInfo{}))
	prev := buf.Len()

	if err := binary.Write(buf, binary.LittleEndian, serialGUIDHob); err != nil {
		return fmt.Errorf("failed to append serial port guid hob to buffer")
	}

	if err := binary.Write(buf, binary.LittleEndian, serialPortInfo); err != nil {
		return fmt.Errorf("failed to append serial port info to buffer")
	}

	if err := alignHOBLength(length, buf.Len()-prev, buf); err != nil {
		return fmt.Errorf("length mismatch when appending end hob")
	}

	*hobLen += length

	return nil
}

func appendUniversalPayloadBase(buf *bytes.Buffer, hobLen *uint64, load uint64) error {
	// Construct universal payload base Hob
	uplBase := constructUnivesralPayloadBase(load)
	uplBaseGUIDHob, err := constructGUIDHob(UniversalPayloadBaseGUID)
	if err != nil {
		return err
	}

	length := uint64(unsafe.Sizeof(EfiHobGUIDType{}) + unsafe.Sizeof(UniversalPayloadBase{}))
	prev := buf.Len()

	if err := binary.Write(buf, binary.LittleEndian, uplBaseGUIDHob); err != nil {
		return fmt.Errorf("failed to append universal payload base guid hob to buffer")
	}

	if err := binary.Write(buf, binary.LittleEndian, uplBase); err != nil {
		return fmt.Errorf("failed to append universal payload base to buffer")
	}

	if err := alignHOBLength(length, buf.Len()-prev, buf); err != nil {
		return fmt.Errorf("length mismatch when appending universal payload base")
	}

	*hobLen += length

	return nil
}

func appendAcpiTableHob(buf *bytes.Buffer, hobLen *uint64) error {
	// Construct universal payload ACPI (RSDP) table Hob
	rsdpTable, err := constructRSDPTable()
	if err != nil {
		return err
	}

	rsdpTableGUIDHob, err := constructGUIDHob(UniversalPayloadAcpiTableGUID)
	if err != nil {
		return err
	}

	length := uint64(unsafe.Sizeof(EfiHobGUIDType{}) + unsafe.Sizeof(UniversalPayloadAcpiTable{}))
	prev := buf.Len()

	if err := binary.Write(buf, binary.LittleEndian, rsdpTableGUIDHob); err != nil {
		return fmt.Errorf("failed to append acpi table guid to buffer")
	}

	if err := binary.Write(buf, binary.LittleEndian, rsdpTable); err != nil {
		return fmt.Errorf("failed to append acpi table to buffer")
	}

	if err := alignHOBLength(length, buf.Len()-prev, buf); err != nil {
		return fmt.Errorf("length mismatch when appending acpi table")
	}

	*hobLen += length

	return nil
}

func appendSmbiosTableHob(buf *bytes.Buffer, hobLen *uint64) error {
	// Construct SMBIOS Hob
	smbiosTable, err := constructSmbiosTable()
	if err != nil {
		return err
	}

	smbiosTableGUIDHob, err := constructGUIDHob(UniversalPayloadSmbiosTableGUID)
	if err != nil {
		return err
	}

	length := uint64(unsafe.Sizeof(EfiHobGUIDType{}) + unsafe.Sizeof(UniversalPayloadSmbiosTable{}))
	prev := buf.Len()

	if err := binary.Write(buf, binary.LittleEndian, smbiosTableGUIDHob); err != nil {
		return fmt.Errorf("failed to append smbios table guid to buffer")
	}

	if err := binary.Write(buf, binary.LittleEndian, smbiosTable); err != nil {
		return fmt.Errorf("failed to append smbios table to buffer")
	}

	if err := alignHOBLength(length, buf.Len()-prev, buf); err != nil {
		return fmt.Errorf("length mismatch when appending smbios table")
	}

	*hobLen += length

	return nil
}

func constructHobList(dst *bytes.Buffer, src *bytes.Buffer, hobLen *uint64) error {
	handoffHob := hobCreateEfiHobHandoffInfoTable(*hobLen)
	if err := binary.Write(dst, binary.LittleEndian, handoffHob); err != nil {
		return fmt.Errorf("failed to append handoff hob to buffer")
	}

	if err := binary.Write(dst, binary.LittleEndian, src.Bytes()); err != nil {
		return fmt.Errorf("failed to append hos list to buffer")
	}

	hobEndHeader := hobCreateEndHob()
	prev := dst.Len()
	length := uint64(unsafe.Sizeof(EfiHobGenericHeader{}))

	if err := binary.Write(dst, binary.LittleEndian, hobEndHeader); err != nil {
		return fmt.Errorf("failed to append end hob")
	}

	if length != (uint64)(dst.Len()-prev) {
		return fmt.Errorf("length mismatch when appending end hob")
	}

	*hobLen += length

	return nil
}

func Load(name string) error {
	fdtLoad, err := getFdtInfo(name)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("failed to read file: %s", name)
	}

	//Step 1, Prepare memory
	mem := kexec.Memory{}

	//Step 2, Insert tianocore raw binary
	mem.Segments.Insert(kexec.NewSegment(data, kexec.Range{Start: uintptr(fdtLoad.Load), Size: uint(len(data))}))

	// Step 3, Prepare HobList
	// TODO: remove hardcode HoB Address here
	hobAddr := fdtLoad.Load - 0x100000
	hobBuf := &bytes.Buffer{}
	hobListBuf := &bytes.Buffer{}
	var hobLen uint64

	if err := appendMemMapHob(hobBuf, &hobLen); err != nil {
		return nil
	}

	if err := appendSerialPortHob(hobBuf, &hobLen); err != nil {
		return nil
	}

	if err := appendUniversalPayloadBase(hobBuf, &hobLen, fdtLoad.Load); err != nil {
		return nil
	}

	if err := appendAcpiTableHob(hobBuf, &hobLen); err != nil {
		return nil
	}

	if err := appendSmbiosTableHob(hobBuf, &hobLen); err != nil {
		return nil
	}

	if err := constructHobList(hobListBuf, hobBuf, &hobLen); err != nil {
		return nil
	}

	mem.Segments.Insert(kexec.NewSegment(hobListBuf.Bytes(), kexec.Range{Start: uintptr(hobAddr), Size: uint(hobLen)}))

	if err := kexec.Load(uintptr(fdtLoad.EntryStart), mem.Segments, 0); err != nil {
		return fmt.Errorf("kexec.Load() error: %v", err)
	}

	if err := boot.Execute(); err != nil {
		return fmt.Errorf("kexec.Execute() error: %v", err)
	}

	return nil
}