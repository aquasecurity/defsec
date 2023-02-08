package ec2

type EC2 struct {
	Instances                  []Instance
	LaunchConfigurations       []LaunchConfiguration
	LaunchTemplates            []LaunchTemplate
	FlowLogs                   []FlowLog
	Addresses                  []Address
	AccountAttributes          []AccountAttribute
	NetworkInterfaces          []NetworkInterface
	VPCs                       []VPC
	VpcPeeringConnections      []VpcPeeringConnection
	VpcEndPoints               []VpcEndPoint
	VpcEndPointService         []VpcEndPointService
	InternetGateways           []InternetGateway
	EgressOnlyInternetGateways []EgressOnlyInternetGateway
	VpnConnections             []VpnConnection
	NatGateways                []NatGateway
	VpnGateways                []VpnGateway
	SecurityGroups             []SecurityGroup
	NetworkACLs                []NetworkACL
	Subnets                    []Subnet
	Volumes                    []Volume
	Images                     []Image
	ResourceTags               []ResourceTags
	RouteTables                []RouteTable
	Snapshots                  []Snapshot
}
