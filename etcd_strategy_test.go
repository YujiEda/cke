package cke

import (
	"strconv"
	"strings"
	"testing"

	"github.com/coreos/etcd/etcdserver/etcdserverpb"
)

type EtcdTestCluster struct {
	Nodes        []*Node
	NodeStatuses map[string]*NodeStatus
	Etcd         EtcdClusterStatus
}

func opCommands(op Operator) []Command {
	var commands []Command
	for {
		commander := op.NextCommand()
		if commander == nil {
			break
		}
		commands = append(commands, commander.Command())
	}
	return commands
}

func Clean3Nodes() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
			{Address: "10.0.0.14"},
			{Address: "10.0.0.15"},
			{Address: "10.0.0.16"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.13": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.14": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.15": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.16": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: false}, HasData: false}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: false,
		},
	}
}

func UnhealthyNonCluster() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 0, Name: "10.0.0.11"},
				"10.0.1.11": {ID: 11, Name: "10.0.1.11"},
				"10.0.1.12": {ID: 12, Name: "10.0.1.12"},
				"10.0.1.13": {ID: 13, Name: "10.0.1.13"},
				"10.0.1.14": {ID: 14, Name: "10.0.1.14"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.1.11": true,
				"10.0.1.12": false,
				"10.0.1.13": true,
				"10.0.1.14": false,
			},
		},
	}
}

func UnhealthyNonControlPlane() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.1.11"},
			{Address: "10.0.1.12"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.1.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.1.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 0, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 1, Name: "10.0.0.12"},
				"10.0.1.11": {ID: 2, Name: "10.0.1.11"},
				"10.0.1.12": {ID: 3, Name: "10.0.1.12"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.1.11": false,
				"10.0.1.12": false,
			},
		},
	}
}

func UnstartedMembers() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
			{Address: "10.0.0.14"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.13": {},
			"10.0.0.14": {},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 0, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 1, Name: "10.0.0.12"},
				"10.0.0.13": {ID: 2, Name: ""},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.0.13": false,
				"10.0.0.14": false,
			},
		},
	}
}

func NewlyControlPlane() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
			{Address: "10.0.0.14"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.13": {},
			"10.0.0.14": {},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 0, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 1, Name: "10.0.0.12"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.0.13": false,
				"10.0.0.14": false,
			},
		},
	}
}

func HealthyNonCluster() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.1.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 1, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 2, Name: "10.0.0.12"},
				"10.0.1.11": {ID: 11, Name: "10.0.1.11"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.1.11": true,
			},
		},
	}
}

func HealthyNonControlPlane() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13"},
			{Address: "10.0.0.14"},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.13": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.14": {},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 1, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 2, Name: "10.0.0.12"},
				"10.0.0.13": {ID: 3, Name: "10.0.0.13"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.0.13": true,
				"10.0.0.14": true,
			},
		},
	}
}

func UnhealthyControlPlane() EtcdTestCluster {
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true}, HasData: true}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy:     false,
			Members:       map[string]*etcdserverpb.Member{},
			InSyncMembers: map[string]bool{},
		},
	}
}

func OutdatedImageControlPlane() EtcdTestCluster {
	oldEtcd := "quay.io/cybozu/etcd:3.2.18-2"
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true, Image: oldEtcd}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true, Image: oldEtcd}, HasData: true}},
			"10.0.0.13": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{Running: true, Image: oldEtcd}, HasData: true}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 1, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 2, Name: "10.0.0.12"},
				"10.0.0.13": {ID: 3, Name: "10.0.0.13"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.0.13": true,
			},
		},
	}
}

func OutdatedParamsControlPlane() EtcdTestCluster {
	oldParams := ServiceParams{ExtraArguments: []string{"--experimental-enable-v2v3"}}
	return EtcdTestCluster{
		Nodes: []*Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
		},
		NodeStatuses: map[string]*NodeStatus{
			"10.0.0.11": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{ExtraParams: oldParams, Image: EtcdImage.Name(), Running: true}, HasData: true}},
			"10.0.0.12": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{ExtraParams: oldParams, Image: EtcdImage.Name(), Running: true}, HasData: true}},
			"10.0.0.13": {Etcd: EtcdStatus{ServiceStatus: ServiceStatus{ExtraParams: oldParams, Image: EtcdImage.Name(), Running: true}, HasData: true}},
		},
		Etcd: EtcdClusterStatus{
			IsHealthy: true,
			Members: map[string]*etcdserverpb.Member{
				"10.0.0.11": {ID: 1, Name: "10.0.0.11"},
				"10.0.0.12": {ID: 2, Name: "10.0.0.12"},
				"10.0.0.13": {ID: 3, Name: "10.0.0.13"},
			},
			InSyncMembers: map[string]bool{
				"10.0.0.11": true,
				"10.0.0.12": true,
				"10.0.0.13": true,
			},
		},
	}
}

func BootstrapCommands(targets ...string) []Command {
	hosts := strings.Join(targets, ",")
	commands := []Command{
		{Name: "image-pull", Target: EtcdImage.Name()},
		{Name: "setup-etcd-certificates", Target: hosts},
		{Name: "volume-create", Target: hosts},
	}
	for _, addr := range targets {
		commands = append(commands, Command{Name: "run-container", Target: addr})
	}
	var endpoints []string
	for _, target := range targets {
		endpoints = append(endpoints, "https://"+target+":2379")
	}
	commands = append(commands, Command{Name: "wait-etcd-sync", Target: strings.Join(endpoints, ",")})
	commands = append(commands, Command{Name: "setup-etcd-auth", Target: strings.Join(endpoints, ",")})
	return commands
}

func AddMemberCommands(addr string) []Command {
	return []Command{
		{Name: "image-pull", Target: EtcdImage.Name()},
		{Name: "stop-container", Target: addr},
		{Name: "volume-remove", Target: addr},
		{Name: "volume-create", Target: addr},
		{Name: "setup-etcd-certificates", Target: addr},
		{Name: "add-etcd-member", Target: addr},
		{Name: "wait-etcd-sync", Target: "https://" + addr + ":2379"},
	}
}

func RemoveMemberCommands(ids ...uint64) []Command {
	var ss []string
	for _, id := range ids {
		ss = append(ss, strconv.FormatUint(id, 10))
	}
	return []Command{{Name: "remove-etcd-member", Target: strings.Join(ss, ",")}}
}

func DestroyMemberCommands(cps []string, addrs []string, ids []uint64) []Command {
	var endpoints []string
	for _, cp := range cps {
		endpoints = append(endpoints, "https://"+cp+":2379")
	}
	var commands []Command
	for i, addr := range addrs {
		commands = append(commands,
			Command{Name: "remove-etcd-member", Target: strconv.FormatUint(ids[i], 10)},
			Command{Name: "wait-etcd-sync", Target: strings.Join(endpoints, ",")},
			Command{Name: "stop-container", Target: addr},
			Command{Name: "volume-remove", Target: addr},
		)
	}
	return commands
}

func UpdateImageMemberCommands(cps []string) []Command {
	var endpoints []string
	for _, cp := range cps {
		endpoints = append(endpoints, "https://"+cp+":2379")
	}
	var commands []Command
	for _, cp := range cps {
		commands = append(commands,
			Command{Name: "wait-etcd-sync", Target: strings.Join(endpoints, ",")},
			Command{Name: "image-pull", Target: EtcdImage.Name()},
			Command{Name: "stop-container", Target: cp},
			Command{Name: "run-container", Target: cp},
		)
	}
	return commands
}

func RestartCommands(cps []string) []Command {
	var endpoints []string
	for _, cp := range cps {
		endpoints = append(endpoints, "https://"+cp+":2379")
	}
	var commands []Command
	for _, cp := range cps {
		commands = append(commands,
			Command{Name: "wait-etcd-sync", Target: strings.Join(endpoints, ",")},
			Command{Name: "stop-container", Target: cp},
			Command{Name: "run-container", Target: cp},
		)
	}
	return commands
}

func WaitMemberCommands(cps []string) []Command {
	var endpoints []string
	for _, cp := range cps {
		endpoints = append(endpoints, "https://"+cp+":2379")
	}
	return []Command{
		{Name: "wait-etcd-sync", Target: strings.Join(endpoints, ",")},
	}
}

func testEtcdDecideToDo(t *testing.T) {
	cases := []struct {
		Name             string
		Input            EtcdTestCluster
		ExpectedCommands []Command
	}{
		{
			Name:             "Bootstrap",
			Input:            Clean3Nodes(),
			ExpectedCommands: BootstrapCommands("10.0.0.11", "10.0.0.12", "10.0.0.13"),
		},
		{
			Name:             "RemoveUnhealthyNonCluster",
			Input:            UnhealthyNonCluster(),
			ExpectedCommands: RemoveMemberCommands(12, 14),
		},
		{
			Name:  "RemoveUnhealthyNonControlPlane",
			Input: UnhealthyNonControlPlane(),
			ExpectedCommands: DestroyMemberCommands(
				[]string{"10.0.0.11", "10.0.0.12"},
				[]string{"10.0.1.11", "10.0.1.12"},
				[]uint64{2, 3}),
		},
		{
			Name:             "StartUnstartedMember",
			Input:            UnstartedMembers(),
			ExpectedCommands: AddMemberCommands("10.0.0.13"),
		},
		{
			Name:             "AddNewMember",
			Input:            NewlyControlPlane(),
			ExpectedCommands: AddMemberCommands("10.0.0.13"),
		},
		{
			Name:             "RemoveHealthyNonCluster",
			Input:            HealthyNonCluster(),
			ExpectedCommands: RemoveMemberCommands(11),
		},
		{
			Name:  "RemoveHealthyNonControlPlane",
			Input: HealthyNonControlPlane(),
			ExpectedCommands: DestroyMemberCommands(
				[]string{"10.0.0.11", "10.0.0.12"},
				[]string{"10.0.0.13"},
				[]uint64{3}),
		},
		{
			Name:             "WaitUnhealthyControlPlane",
			Input:            UnhealthyControlPlane(),
			ExpectedCommands: WaitMemberCommands([]string{"10.0.0.11", "10.0.0.12"}),
		},
		{
			Name:             "UpdateOutdatedImage",
			Input:            OutdatedImageControlPlane(),
			ExpectedCommands: UpdateImageMemberCommands([]string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}),
		},
		{
			Name:             "UpdateOutdatedParams",
			Input:            OutdatedParamsControlPlane(),
			ExpectedCommands: RestartCommands([]string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}),
		},
	}

	for _, c := range cases {
		cluster := &Cluster{
			Nodes: c.Input.Nodes,
		}
		clusterStatus := &ClusterStatus{
			NodeStatuses: c.Input.NodeStatuses,
			Etcd:         c.Input.Etcd,
		}

		op := etcdDecideToDo(cluster, clusterStatus)
		if op == nil {
			t.Fatal("op == nil")
		}
		cmds := opCommands(op)
		if len(c.ExpectedCommands) != len(cmds) {
			t.Errorf("[%s] commands length mismatch: %d", c.Name, len(cmds))
			continue
		}
		for i, res := range cmds {
			com := c.ExpectedCommands[i]
			if com.Name != res.Name {
				t.Errorf("[%s] command name mismatch: %s != %s", c.Name, com.Name, res.Name)
			}
			if com.Target != res.Target {
				t.Errorf("[%s] command '%s' target mismatch: %s != %s", c.Name, com.Name, com.Target, res.Target)
			}
		}
	}
}

func TestEtcdStrategy(t *testing.T) {
	t.Skip()
	t.Run("EtcdDecideToDo", testEtcdDecideToDo)
}
