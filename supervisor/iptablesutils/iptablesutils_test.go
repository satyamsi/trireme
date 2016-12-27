package iptablesutils

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/aporeto-inc/mock/gomock"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider/mock"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAppChainPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call AppChainPrefix", func() {

			context := "somecontext"
			index := 345
			prefix := ipu.AppChainPrefix(context, index)

			Convey("Then I should get an AppChainPrefix", func() {

				So(prefix, ShouldEqual, "TRIREME-App-"+context+"-"+strconv.Itoa(index))
			})
		})
	})
}

func TestNetChainPrefix(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call NetChainPrefix", func() {

			context := "somecontext"
			index := 12321312
			prefix := ipu.NetChainPrefix(context, index)

			Convey("Then I should get an NetChainPrefix", func() {

				So(prefix, ShouldEqual, "TRIREME-Net-"+context+"-"+strconv.Itoa(index))
			})
		})
	})
}

func TestDefaultCacheIP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call DefaultCacheIP with empty ip list", func() {

			ip, err := ipu.DefaultCacheIP(nil)

			Convey("Then I should get 0.0.0.0/", func() {

				So(ip, ShouldResemble, "0.0.0.0/0")
				So(err, ShouldBeNil)
			})
		})

		Convey("When I call DefaultCacheIP with ip list", func() {

			ips := policy.NewIPMap(map[string]string{
				policy.DefaultNamespace: "172.0.0.1",
				"otherspace":            "10.10.10.10",
			})
			ip, err := ipu.DefaultCacheIP(ips)

			Convey("Then I should get the first ip", func() {

				So(ip, ShouldEqual, ips.IPs[policy.DefaultNamespace])
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestChainRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call chainRules", func() {

			appChain := "appChain"
			netChain := "netChain"
			ip := "10.10.10.10"
			expectedRules := [][]string{
				{
					appPacketIPTableContext,
					appPacketIPTableSection,
					"-s", ip,
					"-m", "comment", "--comment", "Container specific chain",
					"-j", appChain,
				},
				{
					appAckPacketIPTableContext,
					appPacketIPTableSection,
					"-s", ip,
					"-p", "tcp",
					"-m", "comment", "--comment", "Container specific chain",
					"-j", appChain,
				},
				{
					netPacketIPTableContext,
					netPacketIPTableSection,
					"-d", ip,
					"-m", "comment", "--comment", "Container specific chain",
					"-j", netChain,
				},
			}

			rules := ipu.chainRules(appChain, netChain, ip)

			Convey("Then I should get rules based on appChain, netChain and ip", func() {

				So(len(rules), ShouldEqual, len(expectedRules))
				for index, r := range rules {
					for argindex, a := range r {
						So(a, ShouldEqual, expectedRules[index][argindex])
					}
				}

			})
		})
	})
}

func TestTrapRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call trapRules", func() {

			appChain := "appChain"
			netChain := "netChain"
			network := "10.10.10.10/32"
			netQueue := "netQueue"
			appQueue := "appQueue"

			expectedRules := [][]string{
				// Application Syn and Syn/Ack
				{
					appPacketIPTableContext, appChain,
					"-d", network,
					"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
					"-j", "NFQUEUE", "--queue-balance", appQueue,
				},

				// Application everything else
				{
					appAckPacketIPTableContext, appChain,
					"-d", network,
					"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
					"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
					"-j", "NFQUEUE", "--queue-balance", appQueue,
				},

				// Network side rules
				{
					netPacketIPTableContext, netChain,
					"-s", network,
					"-p", "tcp",
					"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
					"-j", "NFQUEUE", "--queue-balance", netQueue,
				},
			}

			rules := ipu.trapRules(appChain, netChain, network, appQueue, netQueue)

			Convey("Then I should get rules based on appChain, netChain, network, appQueue and netQueue", func() {

				So(len(rules), ShouldEqual, len(expectedRules))
				for index, r := range rules {
					for argindex, a := range r {
						So(a, ShouldEqual, expectedRules[index][argindex])
					}
				}
			})
		})
	})
}

func TestCleanACLs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call CleanACLs in a positive case with no rules", func() {

			emptyRules := []string{}
			mockIpt.EXPECT().ClearChain(appPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(emptyRules, nil)

			mockIpt.EXPECT().ClearChain(appAckPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(emptyRules, nil)

			mockIpt.EXPECT().ClearChain(netPacketIPTableContext, netPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(emptyRules, nil)

			Convey("Then I should get 3 calls to cleanACLSection and no errors", func() {

				err := ipu.CleanACLs()
				So(err, ShouldBeNil)
			})
		})

		Convey("When I call CleanACLs in a positive case with no rules matching chain prefix", func() {

			someRules := []string{"hello", "world"}
			mockIpt.EXPECT().ClearChain(appPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(someRules, nil)

			mockIpt.EXPECT().ClearChain(appAckPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(someRules, nil)

			mockIpt.EXPECT().ClearChain(netPacketIPTableContext, netPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(someRules, nil)

			Convey("Then I should get 3 calls to cleanACLSection and no errors", func() {

				err := ipu.CleanACLs()
				So(err, ShouldBeNil)
			})
		})

		Convey("When I call CleanACLs in a positive case with some rules matching chain prefix", func() {

			someMatchedRules := []string{chainPrefix, "hello", "world"}
			mockIpt.EXPECT().ClearChain(appPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appPacketIPTableContext).Return(someMatchedRules, nil)
			for _, rule := range someMatchedRules {

				if strings.Contains(rule, chainPrefix) {
					mockIpt.ClearChain(appPacketIPTableContext, rule)
					mockIpt.DeleteChain(appPacketIPTableContext, rule)
				}
			}

			mockIpt.EXPECT().ClearChain(appAckPacketIPTableContext, appPacketIPTableSection)
			mockIpt.EXPECT().ListChains(appAckPacketIPTableContext).Return(someMatchedRules, nil)
			for _, rule := range someMatchedRules {

				if strings.Contains(rule, chainPrefix) {
					mockIpt.ClearChain(appAckPacketIPTableContext, rule)
					mockIpt.DeleteChain(appAckPacketIPTableContext, rule)
				}
			}

			mockIpt.EXPECT().ClearChain(netPacketIPTableContext, netPacketIPTableSection)
			mockIpt.EXPECT().ListChains(netPacketIPTableContext).Return(someMatchedRules, nil)
			for _, rule := range someMatchedRules {

				if strings.Contains(rule, chainPrefix) {
					mockIpt.ClearChain(netPacketIPTableContext, rule)
					mockIpt.DeleteChain(netPacketIPTableContext, rule)
				}
			}

			Convey("Then I should get 3 calls to cleanACLSection and no errors", func() {

				err := ipu.CleanACLs()
				So(err, ShouldBeNil)
			})
		})
	})
}

/*
	log.WithFields(log.Fields{
		"package":     "iptablesutils",
		"context":     context,
		"section":     section,
		"chainPrefix": chainPrefix,
	}).Debug("Clean ACL section")

	if err := r.ipt.ClearChain(context, section); err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("Can not clear the section in iptables.")
		return
	}

	rules, err := r.ipt.ListChains(context)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "iptablesutils",
			"context": context,
			"section": section,
			"error":   err.Error(),
		}).Debug("No chain rules found in iptables")
		return
	}

	for _, rule := range rules {

		if strings.Contains(rule, chainPrefix) {
			r.ipt.ClearChain(context, rule)
			r.ipt.DeleteChain(context, rule)
		}
	}

*/

func TestFilterMarkedPacketsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIpt := mockprovider.NewMockIptablesProvider(ctrl)

	Convey("Given I create an iptables utility", t, func() {

		ipu := NewIptableUtils(mockIpt, false)

		Convey("When I call FilterMarkedPackets to induce an error", func() {

			mark := 10
			mockIpt.EXPECT().Insert(appAckPacketIPTableContext, appPacketIPTableSection, 1,
				"-m", "mark",
				"--mark", strconv.Itoa(mark),
				"-j", "ACCEPT").Return(fmt.Errorf("Some Error"))

			err := ipu.FilterMarkedPackets(mark)

			Convey("Then I should get and error", func() {

				So(err, ShouldNotBeNil)
			})
		})
	})
}
