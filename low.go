package coldfire

import (
	"debug/elf"
	"github.com/yalue/elf_reader"
	"os"
	"bytes"
)

func EqualBytes(b1, b2 byte) bool {
	s1 := make([]byte, 1)
	s1[0] = b1
	s2 := make([]byte, 1)
	s2[0] = b2
	return bytes.Equal(s1, s2)
}

func VerifyELFMagic(fname string) bool {
	f := IOReader(fname) 
	_, err := elf.NewFile(f)
	Check(err)
	if err != nil {
		return false
	}
	var ident [16]uint8
	f.ReadAt(ident[0:], 0)
	Check(err)
	if ident[0] == '\x7f' && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F' {
		return true
	}
	return true
}

func IsELF(fname string) bool {
	raw, err := os.ReadFile(fname)
	Check(err)
	_, elf_err := elf_reader.ParseELFFile(raw)
	if elf_err == nil {
		return false
	}
	return true
}

func IsEXE(fname string) bool {
	f := IOReader(fname) 
	_, err := elf.NewFile(f)
	Check(err)
	if err != nil {
		return false
	}
	var ident [16]uint8
	f.ReadAt(ident[0:], 0)
	Check(err)
	if ident[0] == 'M' && ident[1] == 'Z' {
		return true
	}
	return false

}

//func IsELFInfected(fname string) bool {
//
//}

// Checks if an ELF file is designed for AMD x86_64 
func Is64Bit(fname string) bool {
	if IsELF(fname) {
		f := IOReader(fname)
		elfile, err := elf.NewFile(f)
		Check(err)
		if (elfile.Class.String() == "ELFCLASS64" && elfile.Machine.String() == "EM_X86_64") {
			return true
		}
		return false
	} else if IsEXE(fname) {

	}	
	return false
}

func Caves(file string, min_size int) map[string]map[string]int {
	if IsELF(file) {
		elfile, err := elf.Open(file)
		Check(err)
		for _, sect := range elfile.Sections {
			data, _ := sect.Data()
			for off := 0; off < len(data); off++{
				if EqualBytes(data[off], 0x00) {
					
				}
			}
		}
	} else {

	}
	return nil
}