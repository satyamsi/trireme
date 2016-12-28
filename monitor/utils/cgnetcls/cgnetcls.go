//Package cgnetcls implements functionality to manage classid for processes belonging to different cgroups
package cgnetcls

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	log "github.com/Sirupsen/logrus"
)

const (
	basePath = "/sys/fs/cgroup/net_cls/"
	markFile = "/net_cls.classid"
	procs    = "/cgroup.procs"
)

//Empty receiver struct
type netCls struct{}

//Creategroup creates a cgroup/net_cls structure and writes the allocated classid to the file.
//To add a new process to this cgroup we need to write to the cgroup file
func (s *netCls) Creategroup(cgroupname string) error {
	//Create the directory structure
	_, err := os.Stat(basePath)
	if os.IsNotExist(err) {
		syscall.Mount("cgroup", basePath, "cgroup", 0, "net_cls")
	}
	os.MkdirAll((basePath + cgroupname), 0700)
	return nil

}

//AssignMark writes the mark value to net_cls.classid file.
func (s *netCls) AssignMark(cgroupname string, mark uint64) error {
	//16 is the base since the mark file expects hexadecimal values
	markval := "0x" + (strconv.FormatUint(mark, 16))
	fmt.Println(markval)
	if err := ioutil.WriteFile(basePath+cgroupname+markFile, []byte(markval), 0644); err != nil {
		log.WithFields(log.Fields{"package": "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Failed to assing mark ")
		return errors.New("Failed to create write to net_cls.classid file for new cgroup")
	}
	return nil
}

//AddProcess adds the process to the net_cls group
func (s *netCls) AddProcess(cgroupname string, pid int) error {
	_, err := os.Stat(basePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}
	PID := []byte(strconv.Itoa(pid))
	if err := ioutil.WriteFile(basePath+cgroupname+procs, PID, 0644); err != nil {
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
func (s *netCls) RemoveProcess(cgroupname string, pid int) error {
	_, err := os.Stat(basePath + cgroupname)
	if os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "cgnetcls",
			"Error":      err.Error(),
			"cgroupname": cgroupname}).Error("Cgroup does not exist")
		return errors.New("Cgroup does not exist")
	}
	if err := ioutil.WriteFile(basePath+procs, []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.WithFields(log.Fields{"package": "cgnetls",
			"Error":      err.Error(),
			"cgroupname": cgroupname,
			"Pid":        pid}).Error("Failed to add process to cgroup")
		return errors.New("Failed to add process to cgroup")
	}
	return nil
}

//NewCgroupNetController returns a handle to call functions on the cgroup net_cls controller
func NewCgroupNetController() Cgroupnetcls {
	return &netCls{}
}
