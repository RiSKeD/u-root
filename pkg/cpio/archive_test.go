// Copyright 2013-2017 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cpio

import (
	"fmt"
	"syscall"
	"testing"
)

func FuzzWriteReadInMemArchive(f *testing.F) {
	var fileCount uint8 = 20
	var content []byte = []byte("Content")
	var name string = "name"
	var ino, mode, uid, gid, nlink, mtime, major, minor, rmajor, rminor uint64 = 1, S_IFREG | 2, 3, 4, 5, 6, 7, 8, 9, 10
	f.Add(fileCount, content, name, ino, mode, uid, gid, nlink, mtime, major, minor, rmajor, rminor)
	f.Fuzz(func(t *testing.T, fileCount uint8, content []byte, name string, ino uint64, mode uint64, uid uint64, gid uint64, nlink uint64, mtime uint64, major uint64, minor uint64, rmajor uint64, rminor uint64) {
		if len(name) > 20 || len(content) > 200 || fileCount > 32 {
			return
		}
		recs := []Record{}
		var i uint8 = 0
		for ; i < fileCount; i++ {

			recs = append(recs, StaticRecord(content, Info{
				Ino:      ino,
				Mode:     syscall.S_IFREG | mode,
				UID:      uid,
				GID:      gid,
				NLink:    nlink,
				MTime:    mtime,
				FileSize: uint64(len(content)),
				Major:    major,
				Minor:    minor,
				Rmajor:   rmajor,
				Rminor:   rminor,
				Name:     Normalize(name) + fmt.Sprintf("%d", i),
			}))
		}
		arch := ArchiveFromRecords(recs)
		archReader := arch.Reader()

		for _, rec := range recs {
			readRec, err := archReader.ReadRecord()

			if err != nil {
				t.Fatalf("failed to read record from archive")
			}

			if !Equal(rec, readRec) {
				t.Fatalf("records not equal: %v %v", rec, readRec)
			}

			if !arch.Contains(rec) {
				t.Fatalf("record not in archive %v %#v", rec, arch)
			}
		}

	})
}
