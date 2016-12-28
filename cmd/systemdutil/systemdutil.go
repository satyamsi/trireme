package main

import (
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/aporeto-inc/trireme/monitor"
	docopt "github.com/docopt/docopt-go"
)

const (
	remoteMethodCall = "Server.HandleEvent"
	contextID        = "unused"
	//rpcMonitorChannel = "/var/run/monitor.sock"
)

func main() {

	usage := `Command for launching programs with aporeto policy.
Usage:
  aporetolaunch [-h] [--servicename=sname] [--command=bin] [--params=parameter...] [--metadata=keyvalue...]
 aporetolaunch --version
Options:
  -h --help                              show this help message and exit
  -s sname --servicename=sname           the name of the service to be launched
  -c bin --command=bin                   The command to run
  -p parameters --params=parameters      the parameter passed to the command
  -m keyvalue --metadata=keyvalue        The metadata/labels associated with a service
  --version                              show version and exit
  `
	stderrlogger := log.New(os.Stderr, "", 0)

	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)
	servicename, ok := arguments["--servicename"].(string)
	command, _ := arguments["--command"].(string)
	params := arguments["--params"].([]string)
	metadata := arguments["--metadata"]
	metadatamap := make(map[string]string)
	for _, element := range metadata.([]string) {
		keyvalue := strings.Split(element, "=")
		metadatamap[keyvalue[0]] = keyvalue[1]
	}
	//Make RPC call
	//In Response i expect a status of OK or !OK
	client, err := net.Dial("unix", monitor.Rpcaddress)
	if err != nil {
		// log.WithFields(log.Fields{"package":"aporetolaunch",
		// 	"error":err.Error()}).Error("Cannot connect to policy process")
		stderrlogger.Fatalf("Cannot connect to policy process %s", err)
	}
	if !ok {
		servicename = command
	}
	request := &monitor.EventInfo{
		PUID:      servicename,
		Name:      command,
		Tags:      metadatamap,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: "create",
	}
	response := &monitor.RPCResponse{}

	rpcClient := jsonrpc.NewClient(client)
	err = rpcClient.Call(remoteMethodCall, request, response)
	if err != nil {
		// log.WithFields(log.Fields{"package":"aporetolaunch",
		// 	"error":err.Error()}).Error("Remote Call to policy process failed")
		stderrlogger.Fatalf("Policy Server call failed %s", err.Error())
		os.Exit(-1)
	}
	if len(response.Error) > 0 {
		//Policy failed
		stderrlogger.Fatalf("Your policy does not allow you to run this command")

	}
	syscall.Exec(command, params, os.Environ())

}
