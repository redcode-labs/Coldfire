package coldfire

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// ReadFile is used to read a given file and return its data as a string.
func ReadFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func IOReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	Check(err)
	return r
}


// WriteFile is used to write data into a given file.
func WriteFile(filename, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}

	return nil
}

// FilesPattern is used to return data mapped to files
// where their filenames match a given pattern.
func FilesPattern(directory, pattern string) (map[string]string, error) {
	out_map := map[string]string{}
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		fl, err := ReadFile(f.Name())

		if err != nil {
			return nil, err
		}

		if strings.Contains(fl, pattern) {
			out_map[f.Name()], err = ReadFile(f.Name())
			if err != nil {
				return nil, err
			}
		}
	}

	return out_map, nil
}

// CopyFile copies a file from one directory to another.
func CopyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// MakeZip packs a list of given files within a zip archive.
func MakeZip(zip_file string, files []string) error {
	newZipFile, err := os.Create(zip_file)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	for _, file := range files {
		fileToZip, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fileToZip.Close()
		info, err := fileToZip.Stat()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = file
		header.Method = zip.Deflate
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, fileToZip)
		if err != nil {
			return err
		}
	}

	return nil
}
