// Package policy describes a generic interface for retrieving policies.
// Different implementations are possible for environments such as Kubernetes,
// Mesos or other custom environments. An implementation has to provide
// a method for retrieving policy based on the metadata associated with the container
// and deleting the policy when the container dies. It is up to the implementation
// to decide how to generate the policy.
// The package also defines the basic data structure for communicating policy
// information. The implementations are responsible for providing all the necessary
// data.
package policy

// A RuntimeReader allows to get the specific parameters stored in the Runtime
type RuntimeReader interface {

	// Pid returns the Pid of the Runtime.
	Pid() int

	// Name returns the process name of the Runtime.
	Name() string

	// Tag retuns the value of the given tag.
	Tag(string) (string, bool)

	// Tags returns a copy of the list of the tags.
	Tags() *TagsMap

	// DefaultIPAddress retutns the default IP address.
	DefaultIPAddress() (string, bool)

	// IPAddresses returns a copy of all the IP addresses.
	IPAddresses() *IPMap
}

// InfoInteractor is the interface for setting up policy before providing to trireme
type InfoInteractor interface {

	// Clone returns a copy of the policy
	Clone() *PUPolicy

	// IngressACLs returns a copy of IPRuleList
	IngressACLs() *IPRuleList

	// EgressACLs returns a copy of IPRuleList
	EgressACLs() *IPRuleList

	// ReceiverRules returns a copy of TagSelectorList
	ReceiverRules() *TagSelectorList

	// TransmitterRules returns a copy of TagSelectorList
	TransmitterRules() *TagSelectorList

	// Identity  returns a copy of the identity
	Indentity() *TagsMap

	// Annotations returns a copy of the Annotations
	Annotations() *TagsMap

	// DefaultIPAddress returns the default IP address for the processing unit
	DefaultIPAddress() (string, bool)
}
