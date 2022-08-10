// Copyright 2022 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// du - estimate and display disk usage of files
//
// Synopsis:
//     du [OPTIONS] [FILE]...
//
// Options:
//      -a:    write count of all files, not just directories
//      -h:    print sizes in human readable format
//      -s:    display only total for each directory
//  --time:    show time of last modification of any file or directory
package main

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

var (
	all           = flag.BoolP("all", "a", false, "write count of all files, not just directories")
	humanReadable = flag.BoolP("human-readable", "h", false, "print sizes in human readable format")
	summarize     = flag.BoolP("summarize", "s", false, "display only total for  each directory")
	timeFlag      = flag.Bool("time", false, "show time of last modification of any file or directory")
)

type DirProperties struct {
	modtime        time.Time
	size           int64
	fileProperties []FileProperties
}
type FileProperties struct {
	path    string
	modtime time.Time
	size    int64
}

type SizeUnit int64

const (
	None SizeUnit = iota
	Kilobyte
	megabyte
	Gigabyte
)

func (s SizeUnit) String() string {
	switch s {
	case None:
		return ""
	case Kilobyte:
		return "K"
	case megabyte:
		return "M"
	case Gigabyte:
		return "G"
	default:
		return ""
	}
}

const (
	YYYYMMDDHHMM = "2006-01-02 15:04"
)

//
func du(w io.Writer, paths []string) error {

	if *summarize && *all {
		return fmt.Errorf("cannot both summarize and show all entries")
	}

	// mapping all required file informations to their directory path
	filesOfDirsList := make(map[string][]FileProperties)
	var logOutput []FileProperties

	processablePaths, errs := removeInvalidPaths(paths)

	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(w, "du: %v\n", err)
		}
	}

	if len(processablePaths) == 0 {
		return nil
	}

	// create list of directories and their sizes as well as map of files inside them for each unique path
	for _, path := range processablePaths {

		dirPropertiesOfPath, filePropertiesOfPath, err := processPath(w, path)

		if err != nil {
			return fmt.Errorf("du: %v", err)
		}

		if dirPropertiesOfPath != nil {
			// sort directory paths in reverse order (TODO: fix order of subdirectories)
			sort.SliceStable(*dirPropertiesOfPath, func(i, j int) bool {
				return !sort.StringsAreSorted([]string{(*dirPropertiesOfPath)[i].path, (*dirPropertiesOfPath)[j].path})
			})

			logOutput = append(logOutput, *dirPropertiesOfPath...)

			if filePropertiesOfPath != nil {
				// add FileProperties of files in a directory to map of all paths
				for dirPath, filePropertiesOfDir := range *filePropertiesOfPath {
					filesOfDirsList[dirPath] = append(filesOfDirsList[dirPath], filePropertiesOfDir...)
				}
			}
		}
	}

	if len(logOutput) == 0 {
		return nil
	}

	// update sizes of individual directories
	for idx := range logOutput {
		for _, file := range filesOfDirsList[logOutput[idx].path] {
			logOutput[idx].size += file.size
		}
	}

	// propagate sizes to parent directories
	for idx, parent := range logOutput {
		for _, fp := range logOutput {
			if parent.path == filepath.Dir(fp.path) && parent.path != fp.path {
				logOutput[idx].size += fp.size
			}
		}
	}

	// if summarize flag is set, only print out directory sizes of the passed path arguments and no subdirectories
	if *summarize {
		var pathOutput []FileProperties
		for _, path := range processablePaths {
			for idx, _ := range logOutput {
				if path == logOutput[idx].path {
					pathOutput = append(pathOutput, logOutput[idx])
				}
			}
		}
		writeOutput(w, &pathOutput)
		return nil
	}

	//add files to output if flag is set
	var logOutputWithFiles []FileProperties
	if *all {
		for _, elem := range logOutput {
			files := filesOfDirsList[elem.path]
			logOutputWithFiles = append(logOutputWithFiles, files...)
			logOutputWithFiles = append(logOutputWithFiles, elem)
		}
	} else {
		logOutputWithFiles = logOutput
	}

	if len(logOutputWithFiles) > 0 {
		writeOutput(w, &logOutputWithFiles)
	}

	return nil
}

func dedupStrings(list []string) []string {
	var newList []string
	seen := make(map[string]struct{})
	for _, s := range list {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			newList = append(newList, s)
		}
	}
	return newList
}

// Return only nonduplicate, accessable and cleaned paths. Duplicate occurences are either the same path or any of their subdirectories.
func removeInvalidPaths(paths []string) ([]string, []error) {
	var cleanedPaths []string
	var hadError []error

	for _, path := range paths {
		absPath, err := filepath.Abs(path)

		if err != nil {
			hadError = append(hadError, err)
			continue
		}

		cleanedPath := filepath.Clean(absPath)
		_, err = os.Stat(cleanedPath)

		if err != nil {
			hadError = append(hadError, err)
			continue
		}
		cleanedPaths = append(cleanedPaths, cleanedPath)
	}

	for path1 := range cleanedPaths {
		for path2 := range cleanedPaths {
			if path1 != path2 {
				if filepath.HasPrefix(cleanedPaths[path1], cleanedPaths[path2]) {
					cleanedPaths[path1] = cleanedPaths[path2]
				} else if filepath.HasPrefix(cleanedPaths[path2], cleanedPaths[path1]) {
					cleanedPaths[path2] = cleanedPaths[path1]
				}
			}
		}
	}

	noneDupPaths := dedupStrings(cleanedPaths)

	return noneDupPaths, hadError
}

// walk path and return properties of directory and map of files inside the directory
func processPath(w io.Writer, rootPath string) (*[]FileProperties, *map[string][]FileProperties, error) {
	var dirProperties []FileProperties
	filePropertiesOfDir := make(map[string][]FileProperties)

	rootPath = filepath.Clean(rootPath)

	info, err := os.Stat(rootPath)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot access '%v': No such file or directory\n", rootPath)
	}

	// if rootpath is not a directory, return only the information for the file itself
	if !info.IsDir() {
		// get fileSize
		fsys := info.Sys().(*syscall.Stat_t)
		err = syscall.Stat(rootPath, fsys)

		if err != nil {
			return nil, nil, fmt.Errorf("cannot get required information of the filesystem for %v", err)
		}

		fileSize := fsys.Blocks * fsys.Blksize >> 13

		return &[]FileProperties{{rootPath, info.ModTime(), fileSize}}, nil, nil
	}

	err = filepath.Walk(rootPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(w, "failed to access file %v in %v: %v\n", path, rootPath, err)
			return err
		}

		// get blocks and blocksize of file
		fsys := info.Sys().(*syscall.Stat_t)
		err = syscall.Stat(path, fsys)

		if err != nil {
			fmt.Fprintf(w, "failed to access file %v in %v: %v\n", path, rootPath, err)
			return err
		}

		fileSize := fsys.Blocks * fsys.Blksize >> 13

		if !info.Mode().IsRegular() && !info.IsDir() {
			dirPath := filepath.Dir(path)
			filePropertiesOfDir[dirPath] = append(filePropertiesOfDir[dirPath], FileProperties{path, info.ModTime(), fileSize})
			return filepath.SkipDir
		}

		if info.IsDir() {
			dirProperties = append(dirProperties, FileProperties{path, info.ModTime(), fileSize})
			return nil
		}

		dirPath := filepath.Dir(path)
		filePropertiesOfDir[dirPath] = append(filePropertiesOfDir[dirPath], FileProperties{path, info.ModTime(), fileSize})
		return nil

	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to access path %v\n", rootPath)
	}

	return &dirProperties, &filePropertiesOfDir, nil
}

// writes output to passed io.Writer. if human-readable lag or time flag is set, format output sizes accordingly
func writeOutput(w io.Writer, fileProperties *[]FileProperties) {

	var sizesAsFloats []float64
	var sizesAsStrings []string
	var sizesUnits []SizeUnit
	maxLenghtSizes := 1

	for idx, properties := range *fileProperties {
		sizeUnit := None
		var size string
		if *humanReadable {
			sizeUnit = Kilobyte
			sizesAsFloats = append(sizesAsFloats, float64(properties.size))
			for sizesAsFloats[idx] > 1024 && sizeUnit < Gigabyte {
				sizeUnit++
				sizesAsFloats[idx] /= 1024
			}
			sizesAsFloats[idx] = math.Ceil(sizesAsFloats[idx]*10) / 10
			size = fmt.Sprintf("%.1f", sizesAsFloats[idx])
			size = strings.TrimSuffix(size, ".0")
		} else {
			size = fmt.Sprintf("%d", properties.size)
		}

		if len(size) > maxLenghtSizes {
			maxLenghtSizes = len(size)
		}
		sizesAsStrings = append(sizesAsStrings, size)
		sizesUnits = append(sizesUnits, sizeUnit)
	}

	for idx, properties := range *fileProperties {
		sizesAsStrings[idx] = fmt.Sprintf("%-*v%v", maxLenghtSizes, sizesAsStrings[idx], sizesUnits[idx])
		if !*timeFlag {
			fmt.Fprintf(w, "%v\t%v\n", sizesAsStrings[idx], properties.path)
		} else {
			fmt.Fprintf(w, "%v\t%v\t%v\n", sizesAsStrings[idx], properties.modtime.Format(YYYYMMDDHHMM), properties.path)
		}
	}

}

func run(w io.Writer, paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("du: no arguments passed to du")
	}
	return du(w, paths)

}

func main() {
	flag.Parse()
	if err := run(os.Stdout, flag.Args()); err != nil {
		log.Fatalf("%v", err)
	}

}
