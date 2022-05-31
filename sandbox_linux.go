package coldfire

import "os"

func sandboxFilepath() bool {
	out, _ := cmdOut("systemd-detect-virt")
	if out != "none\n" {
	}
	return out != "none\n"
}

// HOTFIX - below function returns false negative, because
// installation of minio/pkg/disk package eats dick on absolutely every platform.
// Rewriting this function using CmdOut() or 'syscall' package would be much appreciated :>
func sandboxDisk(size int) bool {
	v := false
	//d := "/"
	//di, _ := disk.GetInfo(d)
	//x := strings.Replace(humanize.Bytes(di.Total), "GB", "", -1)
	//x = strings.Replace(x, " ", "", -1)
	//z, err := strconv.Atoi(x)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//if z < size {
	//	v = true
	//}
	return v
}

func sandboxTmp(entries int) bool {
	tmp_dir := "/tmp"
	files, err := os.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}
