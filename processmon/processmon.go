package ProcessMon

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

var processName = "./remote_enforcer"

//ProcessMon exported
type ProcessMon struct {
	activeProcesses *cache.Cache
}

var launcher *ProcessMon

//ProcessInfo exported
type processInfo struct {
	contextID string
	RPCHdl    rpcwrapper.RPCClient
	process   *os.Process
	deleted   bool
}

//var activeProcesses = cache.NewCache(nil)

type exitStatus struct {
	process    int
	contextID  string
	exitStatus error
}

var childExitStatus = make(chan exitStatus, 100)
var netnspath string

// ErrEnforcerAlreadyRunning Exported
var ErrEnforcerAlreadyRunning = errors.New("Enforcer already running in this context")

// ErrSymLinkFailed Exported
var ErrSymLinkFailed = errors.New("Failed to create symlink for use by ip netns")

// ErrFailedtoLaunch Exported
var ErrFailedtoLaunch = errors.New("Failed to launch enforcer")

// ErrProcessDoesNotExists Exported
var ErrProcessDoesNotExists = errors.New("Process in that context does not exist")

//ErrBinaryNotFound Exported
var ErrBinaryNotFound = errors.New("Enforcer Binary not found")

func init() {

	netnspath = "/var/run/netns/"
	go collectChildExitStatus()
}

//SetnsNetPath -- only planned consumer is unit test
//Call this function if you expect network namespace links to be created in a separate path
func (p *ProcessMon) SetnsNetPath(netpath string) {

	netnspath = netpath
}

//GetExitStatus reports if the process is marked for deletion or deleted
func (p *ProcessMon) GetExitStatus(contextID string) bool {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
		}).Info("Process already dead")
		return true
	}
	return (s.(*processInfo)).deleted
}

//SetExitStatus marks the process for deletion
func (p *ProcessMon) SetExitStatus(contextID string, status bool) error {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
		}).Error("Process already dead")
		return err
	}
	val := s.(*processInfo)
	val.deleted = status
	p.activeProcesses.AddOrUpdate(contextID, val)
	return nil
}

//KillProcess sends a rpc to the process to exit failing which it will kill the process
func (p *ProcessMon) KillProcess(contextID string) {

	s, err := p.activeProcesses.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"msg": "Process already killed",
		}).Info("Process already killed or never launched")
		return
	}
	req := &rpcwrapper.Request{}
	resp := &rpcwrapper.Response{}
	req.Payload = s.(*processInfo).process.Pid
	err = s.(*processInfo).RPCHdl.RemoteCall(contextID, "Server.EnforcerExit", req, resp)
	if err != nil {
		s.(*processInfo).process.Kill()
	}
	s.(*processInfo).RPCHdl.DestroyRPCClient(contextID)
	os.Remove(netnspath + contextID)
	p.activeProcesses.Remove(contextID)

}

//private function uses with test
func setprocessname(name string) {

	processName = name
}

//collectChildExitStatus is an async function which collects status for all launched child processes
func collectChildExitStatus() {

	for {
		exitStatus := <-childExitStatus
		log.WithFields(log.Fields{"package": "ProcessMon",
			"ContextID":  exitStatus.contextID,
			"pid":        exitStatus.process,
			"ExitStatus": exitStatus.exitStatus,
		}).Info("Enforcer exited")
	}
}

//LaunchProcess prepares the environment for the new process and launches the process
func (p *ProcessMon) LaunchProcess(contextID string, refPid int, rpchdl rpcwrapper.RPCClient) error {

	_, err := p.activeProcesses.Get(contextID)
	if err == nil {
		return nil
	}
	_, staterr := os.Stat(netnspath)
	if staterr != nil {
		mkerr := os.MkdirAll(netnspath, os.ModeDir)
		if mkerr != nil {
			log.WithFields(log.Fields{"package": "ProcessMon",
				"error": mkerr,
			}).Info("Could not create directory")

		}
	}

	linkErr := os.Symlink("/proc/"+strconv.Itoa(refPid)+"/ns/net",
		netnspath+contextID)
	if linkErr != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": linkErr,
		}).Error(ErrSymLinkFailed)
		//return linkErr
	}
	namedPipe := "SOCKET_PATH=/tmp/" + strconv.Itoa(refPid) + ".sock"

	cmdName := processName
	cmdArgs := []string{contextID}
	cmd := exec.Command(cmdName, cmdArgs...)
	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	statschannelenv := "STATSCHANNEL_PATH=" + rpcwrapper.StatsChannel
	cmd.Env = append(os.Environ(), []string{namedPipe, statschannelenv, "CONTAINER_PID=" + strconv.Itoa(refPid)}...)
	err = cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"package": "ProcessMon",
			"error": err,
			"PATH":  cmdName,
		}).Error("Enforcer Binary not present in expected location")
		//Cleanup resources
		os.Remove(netnspath + contextID)
		return ErrBinaryNotFound
	}
	exited := make(chan int, 2)
	go func() {
		pid := cmd.Process.Pid
		i := 0
		for i < 2 {
			<-exited
			i++
		}
		status := cmd.Wait()
		childExitStatus <- exitStatus{process: pid, contextID: contextID, exitStatus: status}
	}()
	//processMonWait(cmd, contextID)
	go func() {
		io.Copy(os.Stdout, stdout)
		exited <- 1
	}()
	go func() {
		io.Copy(os.Stderr, stderr)
		exited <- 1
	}()
	rpchdl.NewRPCClient(contextID, "/tmp/"+strconv.Itoa(refPid)+".sock")
	p.activeProcesses.Add(contextID, &processInfo{contextID: contextID,
		process: cmd.Process,
		RPCHdl:  rpchdl,
		deleted: false})

	return nil
}

//NewProcessMon is a method to create a new processmon
func NewProcessMon() ProcessManager {

	launcher = &ProcessMon{activeProcesses: cache.NewCache(nil)}
	return launcher
}

//GetProcessMonHdl will ensure that we return an existing handle if one has been created.
//or return a new one if there is none
//This needs locks
func GetProcessMonHdl() ProcessManager {

	if launcher == nil {
		return NewProcessMon()
	}
	return launcher

}
