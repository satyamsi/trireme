//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

import (
	"errors"
	"io/ioutil"
	"strconv"
	"syscall"
)

const (
	basePath = "/sys/fs/cgroup/net_cls/"
	markFile = "/net_cls.classid"
	procs    = "cgroup.procs"
)

//Creategroup creates a cgroup/net_cls structure and writes the allocated classid to the file.
//To add a new process to this cgroup we need to write to the cgroup file
func Creategroup(cgroupname string) error {
	//Create the directory structure
	_, err = os.Stat(basePath)
	if os.NotExists(err) {
		syscall.Mount("cgroup", basePath, "cgroup", 0, "net_cls")
	}
	os.MkdirAll((basePath + cgroupname), 0700)
	return nil

}

//AssignMark writes the mark value to net_cls.classid file.
func AssignMark(cgroupname string, uint64 mark) error {
	//16 is the base since the mark file expects hexadecimal values
	if err := ioutil.WriteFile(basePath+cgroupname+markFile, []byte(strconv.FormatUInt(mark, 16)), 0700); err != nil {
		log.WithFields(log.Fields{"package": "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Failed to create cgroup")
		return errors.New("Failed to create write to net_cls.classid file for new cgroup")
	}
	return nil
}

//AddProcess adds the process to the net_cls group
func AddProcess(cgroupname string, pid int) error {
	_, err = os.Stat(basePath + cgroupname)
	if os.NotExists(err) {
		log.WithFields(log.Fields{"package": "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}
	if err := ioutil.WriteFile(basePath+cgroupname+procs, []byte(strconv.FormatInt(pid, 10)), 0700); err != nil {
		log.WithFields(log.Fields{"package": "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
			"Pid":        pid}).Error("Failed to add process to cgroup")
		return errors.New("Failed to add process to cgroup")
	}
	return nil
}

//RemoveProcess removes the process from the cgroup by writing the pid to the
//top of net_cls cgroup cgroup.procs
func RemoveProcess(cgroupname string, pid int) {
	_, err = os.Stat(basePath + cgroupname)
	if os.NotExists(err) {
		log.WithFields(log.Fields{"package": "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}
	if err := ioutil.WriteFile(basePath+procs, []byte(strconv.FormatInt(pid, 10)), 0700); err != nil {
		log.WithFields(log.Fields{"package": "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
			"Pid":        pid}).Error("Failed to add process to cgroup")
		return errors.New("Failed to add process to cgroup")
	}
	return nil
}
