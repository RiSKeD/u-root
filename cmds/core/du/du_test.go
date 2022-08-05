package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestDu(t *testing.T) {
	var want, got bytes.Buffer

	t.Run("directory containing files with different sizes", func(t *testing.T) {
		defer cleanup(&want, &got)
		tmpDir := t.TempDir()
		basePath := "a"
		path := filepath.Join(tmpDir, basePath)
		if err := os.Mkdir(path, 0777); err != nil {
			t.Fatalf("err in os.Mkdir: %v", err)
		}

		if err := setupDifferentFileSizes(t, &want, path, 0xFFFF); err != nil {
			t.Fatalf("setup failed: %v", err)
		}
		*all = true

		du(&got, []string{path})

		assertEqual(t, &got, &want)
	})

	// t.Run("directory with multiple layers", func(t *testing.T) {
	// 	defer cleanup(&want, &got)

	// 	_, dirPath, err := setupMultipleLayers(t)
	// 	if err != nil {
	// 		t.Fatalf("failed to create directory structur")
	// 	}

	// 	// fillBuffer(&want, *fp)
	// 	du(&got, []string{dirPath})

	// 	assertEqual(t, &got, &want)
	// })

	// for _, tt := range []struct {
	// 	name string
	// 	args []string
	// 	err  error
	// }{
	// 	{
	// 		name: "success",
	// 		args: []string{""},
	// 		err:  nil,
	// 	},
	// 	{
	// 		name: "failure",
	// 		args: []string{"foo", "bar"},
	// 		err:  nil,
	// 	},
	// } {
	// 	t.Run(tt.name, func(t *testing.T) {

	// 		if result := run(inFile, outFile, outFile, tt.args); result != tt.status {
	// 			t.Errorf("Want: %d, Got: %d", tt.status, result)
	// 		}
	// 	})
	// }
}

// setup writes a set of files in a directory, putting x bytes (1 <= x <= len(data)) in each file.
func setupDifferentFileSizes(t *testing.T, want io.Writer, path string, testSize int) error {
	_, err := os.Stat(path)

	if err != nil {
		return err
	}

	rand.Seed(time.Now().Unix())
	dataSize := rand.Intn(testSize)
	data := make([]byte, dataSize)
	_, err = rand.Read(data)

	if err != nil {
		return err
	}

	var dirStat syscall.Stat_t
	err = syscall.Stat(path, &dirStat)

	i, j := 0, 1
	var accSize int64
	accSize = dirStat.Blocks * dirStat.Blksize >> 13
	for i < len(data) {
		sizeOfFile := 1 + rand.Intn(len(data)-i)
		filePath := fmt.Sprintf("%v%d", filepath.Join(path, "file_"), j)
		if err := os.WriteFile(filePath, data[i:i+sizeOfFile], 0o666); err != nil {
			return err
		}
		i += sizeOfFile
		// get fileSize
		var fileStat syscall.Stat_t
		err = syscall.Stat(filePath, &fileStat)

		if err != nil {
			return err
		}
		fileSize := fileStat.Blocks * fileStat.Blksize >> 13
		accSize += fileSize
		fmt.Fprintf(want, "%d\t%v\n", fileSize, filePath)

		j++
	}
	fmt.Fprintf(want, "%d\t%v\n", accSize, path)
	return nil
}

func setupMultipleLayers(t *testing.T) (*[]FileProperties, string, error) {
	var fp []FileProperties

	dirPath, err := os.MkdirTemp(os.TempDir(), "top")
	if err != nil {
		return nil, "", err
	}
	dirInfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, "", err
	}

	subDirPath1, err := os.MkdirTemp(dirPath, "sub1")
	if err != nil {
		return nil, "", err
	}
	subDirInfo1, err := os.Stat(subDirPath1)
	if err != nil {
		return nil, "", err
	}

	subDirPath2, err := os.MkdirTemp(subDirPath1, "sub2")
	if err != nil {
		return nil, "", err
	}
	subDirInfo2, err := os.Stat(subDirPath2)
	if err != nil {
		return nil, "", err
	}

	file1, err := os.CreateTemp(dirPath, "fileTop")
	if err != nil {
		return nil, "", err
	}
	fileInfo1, err := file1.Stat()
	if err != nil {
		return nil, "", err
	}

	file2, err := os.CreateTemp(subDirPath1, "fileSub1")
	if err != nil {
		return nil, "", err
	}

	fileInfo2, err := file2.Stat()
	if err != nil {
		return nil, "", err
	}

	file3, err := os.CreateTemp(subDirPath2, "fileSub2")
	if err != nil {
		return nil, "", err
	}

	fileInfo3, err := file3.Stat()
	if err != nil {
		return nil, "", err
	}
	fp = append(fp, FileProperties{fileInfo1.Name(), time.Now(), fileInfo1.Size()})
	fp = append(fp, FileProperties{fileInfo2.Name(), time.Now(), fileInfo2.Size()})
	fp = append(fp, FileProperties{fileInfo3.Name(), time.Now(), fileInfo3.Size()})
	fp = append(fp, FileProperties{subDirPath1, time.Now(), subDirInfo1.Size()})
	fp = append(fp, FileProperties{subDirPath2, time.Now(), subDirInfo2.Size()})
	fp = append(fp, FileProperties{dirPath, time.Now(), dirInfo.Size()})
	return &fp, dirPath, nil
}

func cleanup(want *bytes.Buffer, got *bytes.Buffer) {
	want.Reset()
	got.Reset()
}

func assertEqual(t *testing.T, got, want *bytes.Buffer) {
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want\n%v\ngot\n%v\n", want, got)
	}
}
