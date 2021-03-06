package server

import (
	"reflect"
	"sort"
	"testing"

	"github.com/coreos/etcd/etcdserver/etcdserverpb"
	"github.com/cybozu-go/cke"
	"github.com/cybozu-go/cke/op/clusterdns"
	"github.com/cybozu-go/cke/op/etcd"
	"github.com/cybozu-go/cke/op/k8s"
	"github.com/cybozu-go/cke/op/nodedns"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testClusterName      = "test"
	testServiceSubnet    = "12.34.56.0/24"
	testDefaultDNSDomain = "cluster.local"
	testDefaultDNSAddr   = "10.0.0.53"
)

var testDefaultDNSServers = []string{"8.8.8.8"}

type testData struct {
	Cluster *cke.Cluster
	Status  *cke.ClusterStatus
}

func (d testData) ControlPlane() (nodes []*cke.Node) {
	for _, n := range d.Cluster.Nodes {
		if n.ControlPlane {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

func (d testData) NodeStatus(n *cke.Node) *cke.NodeStatus {
	return d.Status.NodeStatuses[n.Address]
}

func newData() testData {
	cluster := &cke.Cluster{
		Name: testClusterName,
		Nodes: []*cke.Node{
			{Address: "10.0.0.11", ControlPlane: true},
			{Address: "10.0.0.12", ControlPlane: true},
			{Address: "10.0.0.13", ControlPlane: true},
			{
				Address:     "10.0.0.14",
				Labels:      map[string]string{"label1": "value"},
				Annotations: map[string]string{"annotation1": "value"},
				Taints: []corev1.Taint{
					{
						Key:    "taint1",
						Value:  "value1",
						Effect: corev1.TaintEffectNoSchedule,
					},
					{
						Key:    "taint2",
						Effect: corev1.TaintEffectPreferNoSchedule,
					},
				},
			},
			{Address: "10.0.0.15"},
			{Address: "10.0.0.16"},
		},
		ServiceSubnet: testServiceSubnet,
		DNSServers:    testDefaultDNSServers,
	}
	cluster.Options.Kubelet.Domain = testDefaultDNSDomain
	status := &cke.ClusterStatus{
		NodeStatuses: map[string]*cke.NodeStatus{
			"10.0.0.11": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.12": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.13": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.14": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.15": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
			"10.0.0.16": {Etcd: cke.EtcdStatus{ServiceStatus: cke.ServiceStatus{Running: false}, HasData: false}},
		},
	}

	return testData{cluster, status}
}

func (d testData) with(f func(data testData)) testData {
	f(d)
	return d
}

func (d testData) withRivers() testData {
	for _, v := range d.Status.NodeStatuses {
		v.Rivers.Running = true
		v.Rivers.Image = cke.ToolsImage.Name()
		v.Rivers.BuiltInParams = k8s.RiversParams(d.ControlPlane())
	}
	return d
}

func (d testData) withStoppedEtcd() testData {
	for _, n := range d.ControlPlane() {
		d.NodeStatus(n).Etcd.HasData = true
	}
	return d
}

func (d testData) withUnhealthyEtcd() testData {
	d.withStoppedEtcd()
	for _, n := range d.ControlPlane() {
		st := &d.NodeStatus(n).Etcd
		st.Running = true
		st.Image = cke.EtcdImage.Name()
		st.BuiltInParams = etcd.BuiltInParams(n, nil, "")
	}
	return d
}

func (d testData) withHealthyEtcd() testData {
	d.withUnhealthyEtcd()
	st := &d.Status.Etcd
	st.IsHealthy = true
	st.Members = make(map[string]*etcdserverpb.Member)
	st.InSyncMembers = make(map[string]bool)
	for i, n := range d.ControlPlane() {
		st.Members[n.Address] = &etcdserverpb.Member{
			ID:   uint64(i),
			Name: n.Address,
		}
		st.InSyncMembers[n.Address] = true
	}
	return d
}

func (d testData) withAPIServer(serviceSubnet string) testData {
	for _, n := range d.ControlPlane() {
		st := &d.NodeStatus(n).APIServer
		st.Running = true
		st.IsHealthy = true
		st.Image = cke.HyperkubeImage.Name()
		st.BuiltInParams = k8s.APIServerParams(d.ControlPlane(), n.Address, serviceSubnet)
	}
	return d
}

func (d testData) withControllerManager(name, serviceSubnet string) testData {
	for _, n := range d.ControlPlane() {
		st := &d.NodeStatus(n).ControllerManager
		st.Running = true
		st.IsHealthy = true
		st.Image = cke.HyperkubeImage.Name()
		st.BuiltInParams = k8s.ControllerManagerParams(name, serviceSubnet)
	}
	return d
}

func (d testData) withScheduler() testData {
	for _, n := range d.ControlPlane() {
		st := &d.NodeStatus(n).Scheduler
		st.Running = true
		st.IsHealthy = true
		st.Image = cke.HyperkubeImage.Name()
		st.BuiltInParams = k8s.SchedulerParams()
	}
	return d
}

func (d testData) withKubelet(domain, dns string, allowSwap bool) testData {
	for _, n := range d.Cluster.Nodes {
		st := &d.NodeStatus(n).Kubelet
		st.Running = true
		st.IsHealthy = true
		st.Image = cke.HyperkubeImage.Name()
		st.BuiltInParams = k8s.KubeletServiceParams(n)
		st.Domain = domain
		st.AllowSwap = allowSwap
	}
	return d
}

func (d testData) withProxy() testData {
	for _, v := range d.Status.NodeStatuses {
		st := &v.Proxy
		st.Running = true
		st.IsHealthy = true
		st.Image = cke.HyperkubeImage.Name()
		st.BuiltInParams = k8s.ProxyParams()
	}
	return d
}

func (d testData) withAllServices() testData {
	d.withRivers()
	d.withHealthyEtcd()
	d.withAPIServer(testServiceSubnet)
	d.withControllerManager(testClusterName, testServiceSubnet)
	d.withScheduler()
	d.withKubelet(testDefaultDNSDomain, testDefaultDNSAddr, false)
	d.withProxy()
	return d
}

func (d testData) withK8sReady() testData {
	d.withAllServices()
	d.Status.Kubernetes.IsReady = true
	return d
}

func (d testData) withK8sRBACReady() testData {
	d.withK8sReady()
	d.Status.Kubernetes.RBACRoleExists = true
	d.Status.Kubernetes.RBACRoleBindingExists = true
	return d
}

func (d testData) withK8sClusterDNSReady(dnsServers []string, clusterDomain, clusterIP string) testData {
	d.withK8sRBACReady()
	d.Status.Kubernetes.ClusterDNS.ServiceAccountExists = true
	d.Status.Kubernetes.ClusterDNS.RBACRoleExists = true
	d.Status.Kubernetes.ClusterDNS.RBACRoleBindingExists = true
	d.Status.Kubernetes.ClusterDNS.ConfigMap = clusterdns.ConfigMap(clusterDomain, dnsServers)
	d.Status.Kubernetes.ClusterDNS.Deployment = &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"cke.cybozu.com/image":            cke.CoreDNSImage.Name(),
				"cke.cybozu.com/template-version": clusterdns.CoreDNSTemplateVersion,
			},
		},
	}
	d.Status.Kubernetes.ClusterDNS.ServiceExists = true
	d.Status.Kubernetes.ClusterDNS.ClusterDomain = clusterDomain
	d.Status.Kubernetes.ClusterDNS.ClusterIP = clusterIP
	return d
}

func (d testData) withK8sNodeDNSReady() testData {
	var err error

	d.withK8sClusterDNSReady(testDefaultDNSServers, testDefaultDNSDomain, testDefaultDNSAddr)
	d.Status.Kubernetes.NodeDNS.DaemonSet = &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"cke.cybozu.com/image":            cke.UnboundImage.Name(),
				"cke.cybozu.com/template-version": nodedns.UnboundTemplateVersion,
			},
		},
	}
	d.Status.Kubernetes.NodeDNS.ConfigMap = nodedns.ConfigMap(testDefaultDNSAddr, testDefaultDNSDomain, testDefaultDNSServers)
	if err != nil {
		panic(err)
	}
	return d
}

func (d testData) withEtcdBackup() testData {
	d.withEtcdEndpoints()
	d.Cluster.EtcdBackup = cke.EtcdBackup{
		Enabled:  true,
		PVCName:  "etcdbackup-pvc",
		Schedule: "*/1 * * * *",
		Rotate:   14,
	}
	d.Status.Kubernetes.EtcdBackup.Pod = &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "etcdbackup",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: "etcdbackup-pvc",
						},
					},
				},
			},
		},
	}
	d.Status.Kubernetes.EtcdBackup.Service = &corev1.Service{}
	d.Status.Kubernetes.EtcdBackup.ConfigMap = &corev1.ConfigMap{
		Data: map[string]string{
			"config.yml": `backup-dir: /etcdbackup
listen: 0.0.0.0:8080
rotate: 14
etcd:
  endpoints: 
    - https://cke-etcd:2379
  tls-ca-file: /etcd-certs/ca
  tls-cert-file: /etcd-certs/cert
  tls-key-file: /etcd-certs/key
`,
		},
	}
	d.Status.Kubernetes.EtcdBackup.Secret = &corev1.Secret{}
	d.Status.Kubernetes.EtcdBackup.CronJob = &batchv1beta1.CronJob{
		Spec: batchv1beta1.CronJobSpec{
			Schedule: "*/1 * * * *",
		},
	}
	return d
}

func (d testData) withEtcdEndpoints() testData {
	d.withK8sNodeDNSReady()
	d.Status.Kubernetes.EtcdEndpoints = &corev1.Endpoints{
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.0.11"},
					{IP: "10.0.0.12"},
					{IP: "10.0.0.13"},
				},
				Ports: []corev1.EndpointPort{{Port: 2379}},
			},
		},
	}
	return d
}

func (d testData) withNodes(nodes ...corev1.Node) testData {
	d.withEtcdEndpoints()
	d.Status.Kubernetes.Nodes = nodes
	return d
}

func TestDecideOps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		Name        string
		Input       testData
		ExpectedOps []string
	}{
		{
			Name:        "BootRivers",
			Input:       newData(),
			ExpectedOps: []string{"rivers-bootstrap"},
		},
		{
			Name:        "BootRivers2",
			Input:       newData().withHealthyEtcd(),
			ExpectedOps: []string{"rivers-bootstrap"},
		},
		{
			Name: "RestartRivers",
			Input: newData().withRivers().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Rivers.Image = ""
			}),
			ExpectedOps: []string{"rivers-restart"},
		},
		{
			Name: "RestartRivers2",
			Input: newData().withRivers().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Rivers.BuiltInParams.ExtraArguments = nil
			}),
			ExpectedOps: []string{"rivers-restart"},
		},
		{
			Name: "RestartRivers3",
			Input: newData().withRivers().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Rivers.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{"rivers-restart"},
		},
		{
			Name: "StartRestartRivers",
			Input: newData().withRivers().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Rivers.Image = ""
				d.NodeStatus(d.ControlPlane()[1]).Rivers.Running = false
			}),
			ExpectedOps: []string{"rivers-bootstrap", "rivers-restart"},
		},
		{
			Name:        "EtcdBootstrap",
			Input:       newData().withRivers(),
			ExpectedOps: []string{"etcd-bootstrap"},
		},
		{
			Name:        "EtcdStart",
			Input:       newData().withRivers().withStoppedEtcd(),
			ExpectedOps: []string{"etcd-start"},
		},
		{
			Name:        "WaitEtcd",
			Input:       newData().withRivers().withUnhealthyEtcd(),
			ExpectedOps: []string{"etcd-wait-cluster"},
		},
		{
			Name:  "BootK8s",
			Input: newData().withHealthyEtcd().withRivers(),
			ExpectedOps: []string{
				"kube-apiserver-bootstrap",
				"kube-controller-manager-bootstrap",
				"kube-proxy-bootstrap",
				"kube-scheduler-bootstrap",
				"kubelet-bootstrap",
			},
		},
		{
			Name:  "BootK8s2",
			Input: newData().withHealthyEtcd().withRivers().withAPIServer(testServiceSubnet),
			ExpectedOps: []string{
				"kube-controller-manager-bootstrap",
				"kube-proxy-bootstrap",
				"kube-scheduler-bootstrap",
				"kubelet-bootstrap",
			},
		},
		{
			Name:  "RestartAPIServer",
			Input: newData().withAllServices().withAPIServer("11.22.33.0/24"),
			ExpectedOps: []string{
				"kube-apiserver-restart",
			},
		},
		{
			Name: "RestartAPIServer2",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).APIServer.Image = ""
			}),
			ExpectedOps: []string{
				"kube-apiserver-restart",
			},
		},
		{
			Name: "RestartAPIServer3",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).APIServer.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-apiserver-restart",
			},
		},
		{
			Name:  "RestartControllerManager",
			Input: newData().withAllServices().withControllerManager("another", testServiceSubnet),
			ExpectedOps: []string{
				"kube-controller-manager-restart",
			},
		},
		{
			Name: "RestartControllerManager2",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).ControllerManager.Image = ""
			}),
			ExpectedOps: []string{
				"kube-controller-manager-restart",
			},
		},
		{
			Name: "RestartControllerManager3",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).ControllerManager.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-controller-manager-restart",
			},
		},
		{
			Name: "RestartScheduler",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Scheduler.BuiltInParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-scheduler-restart",
			},
		},
		{
			Name: "RestartScheduler2",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Scheduler.Image = ""
			}),
			ExpectedOps: []string{
				"kube-scheduler-restart",
			},
		},
		{
			Name: "RestartScheduler3",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Scheduler.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-scheduler-restart",
			},
		},
		{
			Name:  "RestartKubelet",
			Input: newData().withAllServices().withKubelet("foo.local", "10.0.0.53", false),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name:  "RestartKubelet2",
			Input: newData().withAllServices().withKubelet("", "10.0.0.53", true),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name: "RestartKubelet3",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Kubelet.Image = ""
			}),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name: "RestartKubelet4",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Kubelet.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name: "RestartKubelet5",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Kubelet.Domain = "neco.local"
			}),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name: "RestartProxy",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Proxy.BuiltInParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-proxy-restart",
			},
		},
		{
			Name: "RestartProxy2",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Proxy.Image = ""
			}),
			ExpectedOps: []string{
				"kube-proxy-restart",
			},
		},
		{
			Name: "RestartProxy3",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.Cluster.Nodes[0]).Proxy.ExtraParams.ExtraArguments = []string{"foo"}
			}),
			ExpectedOps: []string{
				"kube-proxy-restart",
			},
		},
		{
			Name:        "WaitKube",
			Input:       newData().withAllServices(),
			ExpectedOps: []string{"wait-kubernetes"},
		},
		{
			Name:  "RBAC",
			Input: newData().withK8sReady(),
			ExpectedOps: []string{
				"create-cluster-dns-configmap",
				"create-cluster-dns-deployment",
				"create-cluster-dns-rbac-role",
				"create-cluster-dns-rbac-role-binding",
				"create-cluster-dns-service",
				"create-cluster-dns-serviceaccount",
				"create-etcd-endpoints",
				"install-rbac-role",
			},
		},
		{
			Name:  "ClusterDNS",
			Input: newData().withK8sRBACReady(),
			ExpectedOps: []string{
				"create-cluster-dns-configmap",
				"create-cluster-dns-deployment",
				"create-cluster-dns-rbac-role",
				"create-cluster-dns-rbac-role-binding",
				"create-cluster-dns-service",
				"create-cluster-dns-serviceaccount",
				"create-etcd-endpoints",
			},
		},
		{
			Name:  "NodeDNS",
			Input: newData().withK8sClusterDNSReady(testDefaultDNSServers, testDefaultDNSDomain, testDefaultDNSAddr),
			ExpectedOps: []string{
				"create-etcd-endpoints",
				"create-node-dns-configmap",
				"create-node-dns-daemonset",
			},
		},
		{
			Name: "UpdateDNSService",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				svc := &corev1.Service{}
				svc.Spec.ClusterIP = "1.1.1.1"
				d.Status.Kubernetes.DNSService = svc
			}),
			ExpectedOps: []string{
				"update-cluster-dns-configmap",
				"update-node-dns-configmap",
			},
		},
		{
			Name:        "EtcdEndpointsCreate",
			Input:       newData().withK8sNodeDNSReady(),
			ExpectedOps: []string{"create-etcd-endpoints"},
		},
		{
			Name: "DNSUpdate1",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Cluster.Options.Kubelet.Domain = "neco.local"
			}),
			ExpectedOps: []string{
				"kubelet-restart",
			},
		},
		{
			Name: "DNSUpdate2",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Cluster.Options.Kubelet.Domain = "neco.local"
				for _, st := range d.Status.NodeStatuses {
					st.Kubelet.Domain = "neco.local"
				}
			}),
			ExpectedOps: []string{
				"update-cluster-dns-configmap",
				"update-node-dns-configmap",
			},
		},
		{
			Name: "DNSUpdate3",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Cluster.DNSServers = []string{"1.1.1.1"}
			}),
			ExpectedOps: []string{
				"update-cluster-dns-configmap",
				"update-node-dns-configmap",
			},
		},
		{
			Name: "DNSUpdate4",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.ClusterDNS.Deployment.Annotations["cke.cybozu.com/template-version"] = "0"
			}),
			ExpectedOps: []string{
				"update-cluster-dns-deployment",
			},
		},
		{
			Name: "NodeDNSUpdate1",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.ClusterDNS.ClusterIP = "10.0.0.54"
			}),
			ExpectedOps: []string{
				"update-node-dns-configmap",
			},
		},
		{
			Name: "NodeDNSUpdate2",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.NodeDNS.DaemonSet.Annotations["cke.cybozu.com/template-version"] = "0"
			}),
			ExpectedOps: []string{
				"update-node-dns-daemonset",
			},
		},
		{
			Name: "EtcdEndpointsUpdate1",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.EtcdEndpoints.Subsets = []corev1.EndpointSubset{}
			}),
			ExpectedOps: []string{"update-etcd-endpoints"},
		},
		{
			Name: "EtcdEndpointsUpdate2",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.EtcdEndpoints.Subsets[0].Ports = []corev1.EndpointPort{}
			}),
			ExpectedOps: []string{"update-etcd-endpoints"},
		},
		{
			Name: "EtcdEndpointsUpdate3",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				d.Status.Kubernetes.EtcdEndpoints.Subsets[0].Addresses = []corev1.EndpointAddress{}
			}),
			ExpectedOps: []string{"update-etcd-endpoints"},
		},
		{
			Name: "NodeLabel1",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeLabel2",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "wrongvalue"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeLabel3",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "10.0.0.14",
					Labels: map[string]string{
						"label1":             "value",
						"cke.cybozu.com/foo": "bar",
					},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeLabel4",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "10.0.0.14",
					Labels: map[string]string{
						"label1":                     "value",
						"sabakan.cke.cybozu.com/foo": "bar",
					},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeAnnotation1",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "10.0.0.14",
					Labels: map[string]string{"label1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeAnnotation2",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "wrongvalue"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeAnnotation3",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "10.0.0.14",
					Labels: map[string]string{"label1": "value"},
					Annotations: map[string]string{
						"annotation1":        "value",
						"cke.cybozu.com/foo": "bar",
					},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeTaint1",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Value:  "value2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeTaint2",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectNoExecute,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeTaint3",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint3",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeTaint4",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
						{
							Key:    "cke.cybozu.com/foo",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: []string{"update-node"},
		},
		{
			Name: "NodeExtraAttrs",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "10.0.0.14",
					Labels: map[string]string{
						"label1":              "value",
						"acke.cybozu.com/foo": "bar",
					},
					Annotations: map[string]string{
						"annotation1":         "value",
						"acke.cybozu.com/foo": "bar",
					},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
						{
							Key:    "acke.cybozu.com/foo",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: nil,
		},
		{
			Name: "RemoveNonClusterNodes",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "10.0.0.20",
				},
			}),
			ExpectedOps: []string{"remove-node"},
		},
		{
			Name: "AllGreen",
			Input: newData().withNodes(corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "10.0.0.14",
					Labels:      map[string]string{"label1": "value"},
					Annotations: map[string]string{"annotation1": "value"},
				},
				Spec: corev1.NodeSpec{
					Taints: []corev1.Taint{
						{
							Key:    "taint1",
							Value:  "value1",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key:    "taint2",
							Effect: corev1.TaintEffectPreferNoSchedule,
						},
					},
				},
			}),
			ExpectedOps: nil,
		},
		{
			Name: "EtcdRemoveNonClusterMember",
			Input: newData().withAllServices().with(func(d testData) {
				d.Status.Etcd.Members["10.0.0.100"] = &etcdserverpb.Member{Name: "10.0.0.100", ID: 3}
			}),
			ExpectedOps: []string{"etcd-remove-member"},
		},
		{
			Name: "EtcdDestroyNonCPMember",
			Input: newData().withAllServices().with(func(d testData) {
				d.Status.Etcd.Members["10.0.0.14"] = &etcdserverpb.Member{Name: "10.0.0.14", ID: 3}
			}),
			ExpectedOps: []string{"etcd-destroy-member"},
		},
		{
			Name: "EtcdReAdd",
			Input: newData().withAllServices().with(func(d testData) {
				d.Status.Etcd.Members["10.0.0.13"].Name = ""
				d.Status.Etcd.Members["10.0.0.13"].ID = 0
			}),
			ExpectedOps: []string{"etcd-add-member"},
		},
		{
			Name: "EtcdIsNotGood",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				// a node is to be added
				delete(d.Status.Etcd.Members, "10.0.0.13")
				delete(d.Status.Etcd.InSyncMembers, "10.0.0.13")
				// but the cluster is not good enough
				delete(d.Status.Etcd.InSyncMembers, "10.0.0.12")
			}),
			ExpectedOps: nil,
		},
		{
			Name: "EtcdAdd",
			Input: newData().withAllServices().with(func(d testData) {
				delete(d.Status.Etcd.Members, "10.0.0.13")
				delete(d.Status.Etcd.InSyncMembers, "10.0.0.13")
			}),
			ExpectedOps: []string{"etcd-add-member"},
		},
		{
			Name: "EtcdRemoveHealthyNonClusterMember",
			Input: newData().withAllServices().with(func(d testData) {
				d.Status.Etcd.Members["10.0.0.100"] = &etcdserverpb.Member{Name: "10.0.0.100", ID: 3}
				d.Status.Etcd.InSyncMembers["10.0.0.100"] = true
			}),
			ExpectedOps: []string{"etcd-remove-member"},
		},
		{
			Name: "EtcdDestroyHealthyNonCPMember",
			Input: newData().withAllServices().with(func(d testData) {
				d.Status.Etcd.Members["10.0.0.14"] = &etcdserverpb.Member{Name: "10.0.0.14", ID: 14}
				d.Status.Etcd.InSyncMembers["10.0.0.14"] = true
			}),
			ExpectedOps: []string{"etcd-destroy-member"},
		},
		{
			Name: "EtcdRestart",
			Input: newData().withAllServices().with(func(d testData) {
				d.NodeStatus(d.ControlPlane()[0]).Etcd.Image = ""
			}),
			ExpectedOps: []string{"etcd-restart"},
		},
		{
			Name: "EtcdBackupCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.ConfigMap = nil
				d.Status.Kubernetes.EtcdBackup.Secret = nil
				d.Status.Kubernetes.EtcdBackup.CronJob = nil
				d.Status.Kubernetes.EtcdBackup.Service = nil
				d.Status.Kubernetes.EtcdBackup.Pod = nil
			}),
			ExpectedOps: []string{"etcdbackup-configmap-create", "etcdbackup-job-create", "etcdbackup-pod-create", "etcdbackup-secret-create", "etcdbackup-service-create"},
		},
		{
			Name: "EtcdBackupConfigMapCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.ConfigMap = nil
			}),
			ExpectedOps: []string{"etcdbackup-configmap-create"},
		},
		{
			Name: "EtcdBackupSecretCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.Secret = nil
			}),
			ExpectedOps: []string{"etcdbackup-secret-create"},
		},
		{
			Name: "EtcdBackupJobCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.CronJob = nil
			}),
			ExpectedOps: []string{"etcdbackup-job-create"},
		},
		{
			Name: "EtcdBackupPodCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.Pod = nil
			}),
			ExpectedOps: []string{"etcdbackup-pod-create"},
		},
		{
			Name: "EtcdBackupServiceCreate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Status.Kubernetes.EtcdBackup.Service = nil
			}),
			ExpectedOps: []string{"etcdbackup-service-create"},
		},
		{
			Name: "EtcdBackupPodUpdate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Cluster.EtcdBackup.PVCName = "new-pvc-name"
			}),
			ExpectedOps: []string{"etcdbackup-pod-update"},
		},
		{
			Name: "EtcdBackupJobUpdate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Cluster.EtcdBackup.Schedule = "* */0 * * *"
			}),
			ExpectedOps: []string{"etcdbackup-job-update"},
		},
		{
			Name: "EtcdBackupConfigMapUpdate",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Cluster.EtcdBackup.Rotate = 10
			}),
			ExpectedOps: []string{"etcdbackup-configmap-update"},
		},
		{
			Name: "EtcdBackupRemove",
			Input: newData().withEtcdBackup().with(func(d testData) {
				d.Cluster.EtcdBackup.Enabled = false
			}),
			ExpectedOps: []string{"etcdbackup-configmap-remove", "etcdbackup-job-remove", "etcdbackup-pod-remove", "etcdbackup-secret-remove", "etcdbackup-service-remove"},
		},
		{
			Name: "Clean",
			Input: newData().withEtcdEndpoints().with(func(d testData) {
				st := d.Status.NodeStatuses["10.0.0.14"]
				st.Etcd.Running = true
				st.Etcd.HasData = true
				st.APIServer.Running = true
				st.ControllerManager.Running = true
				st.Scheduler.Running = true
			}),
			ExpectedOps: []string{
				"stop-etcd",
				"stop-kube-apiserver",
				"stop-kube-controller-manager",
				"stop-kube-scheduler",
			},
		},
	}

	for _, c := range cases {
		ops := DecideOps(c.Input.Cluster, c.Input.Status)
		if len(ops) == 0 && len(c.ExpectedOps) == 0 {
			continue
		}
		opNames := make([]string, len(ops))
		for i, o := range ops {
			opNames[i] = o.Name()
		}
		sort.Strings(opNames)
		if !reflect.DeepEqual(opNames, c.ExpectedOps) {
			t.Errorf("[%s] o names mismatch: %s != %s", c.Name, opNames, c.ExpectedOps)
		}
	OUT:
		for _, o := range ops {
			for i := 0; i < 100; i++ {
				commander := o.NextCommand()
				if commander == nil {
					continue OUT
				}
			}
			t.Fatalf("[%s] Operator.NextCommand() never finished: %s", c.Name, o.Name())
		}
	}
}
