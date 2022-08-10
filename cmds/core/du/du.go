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

// Walk the passed paths and return the disk usage of directories and/or files in accordance to passed flags.
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

		if len(dirPropertiesOfPath) != 0 {
			// sort directory paths in reverse order (TODO: fix order of subdirectories)
			sort.SliceStable(dirPropertiesOfPath, func(i, j int) bool {
				return !sort.StringsAreSorted([]string{(dirPropertiesOfPath)[i].path, (dirPropertiesOfPath)[j].path})
			})

			logOutput = append(logOutput, dirPropertiesOfPath...)

			if len(filePropertiesOfPath) != 0 {
				// add FileProperties of files in a directory to map of all paths
				for dirPath, filePropertiesOfDir := range filePropertiesOfPath {
					filesOfDirsList[dirPath] = append(filesOfDirsList[dirPath], filePropertiesOfDir...)
				}
			}
		}
	}

	if len(logOutput) != 0 {

		// update disk usage of individual directories
		for idx := range logOutput {
			for _, file := range filesOfDirsList[logOutput[idx].path] {
				logOutput[idx].size += file.size
			}
		}

		// propagate disk usage up to parent directories
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
				for idx := range logOutput {
					if path == logOutput[idx].path {
						pathOutput = append(pathOutput, logOutput[idx])
					}
				}
			}
			writeOutput(w, pathOutput)
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
			writeOutput(w, logOutputWithFiles)
		}
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

// walk path and return path, last modified time and disk usage of directory and map of files inside the directory
func processPath(w io.Writer, rootPath string) ([]FileProperties, map[string][]FileProperties, error) {
	var dirProperties []FileProperties
	filePropertiesOfDir := make(map[string][]FileProperties)

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

		return []FileProperties{{rootPath, info.ModTime(), fileSize}}, nil, nil
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

		if info.IsDir() {
			dirProperties = append(dirProperties, FileProperties{path, info.ModTime(), fileSize})
			return nil
		}

		if !info.Mode().IsRegular() {
			dirPath := filepath.Dir(path)
			filePropertiesOfDir[dirPath] = append(filePropertiesOfDir[dirPath], FileProperties{path, info.ModTime(), fileSize})
			return filepath.SkipDir
		}

		dirPath := filepath.Dir(path)
		filePropertiesOfDir[dirPath] = append(filePropertiesOfDir[dirPath], FileProperties{path, info.ModTime(), fileSize})
		return nil

	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to access path %v\n", rootPath)
	}

	return dirProperties, filePropertiesOfDir, nil
}

// Writes output to passed io.Writer.
// If the human-readable flag is set format output as a float + the correct unit size
// If the time flag is set include the last-modified time stamp formatted
func writeOutput(w io.Writer, fileProperties []FileProperties) {

	output := make(map[string]struct {
		stringValue string
		floatValue  float64
		unit        SizeUnit
	}, len(fileProperties))
	maxLengthSizes := 1

	for idx := range fileProperties {
		size := output[fileProperties[idx].path]
		if *humanReadable {
			size.unit = Kilobyte
			size.floatValue = float64(fileProperties[idx].size)
			for size.floatValue > 1024 && size.unit < Gigabyte {
				size.unit++
				size.floatValue /= 1024
			}
			size.floatValue = math.Ceil(size.floatValue*10) / 10
			size.stringValue = strings.TrimSuffix(fmt.Sprintf("%.1f", size.floatValue), ".0")
		} else {
			size.stringValue = fmt.Sprintf("%d", fileProperties[idx].size)
		}

		if len(size.stringValue) > maxLengthSizes {
			maxLengthSizes = len(size.stringValue)
		}
		output[fileProperties[idx].path] = size
	}

	for _, properties := range fileProperties {

		if !*timeFlag {
			fmt.Fprintf(w, "%v%-*v\t%v\n", output[properties.path].stringValue, maxLengthSizes, output[properties.path].unit, properties.path)
		} else {
			fmt.Fprintf(w, "%v%-*v\t%v\t%v\n", output[properties.path].stringValue, maxLengthSizes, output[properties.path].unit, properties.modtime.Format(YYYYMMDDHHMM), properties.path)
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
