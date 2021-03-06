package cke

import (
	"errors"
	"net"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	v1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Node represents a node in Kubernetes.
type Node struct {
	Address      string            `json:"address"       yaml:"address"`
	Hostname     string            `json:"hostname"      yaml:"hostname"`
	User         string            `json:"user"          yaml:"user"`
	ControlPlane bool              `json:"control_plane" yaml:"control_plane"`
	Annotations  map[string]string `json:"annotations"   yaml:"annotations"`
	Labels       map[string]string `json:"labels"        yaml:"labels"`
	Taints       []corev1.Taint    `json:"taints"        yaml:"taints"`
}

// Nodename returns a hostname or address if hostname is empty
func (n *Node) Nodename() string {
	if len(n.Hostname) == 0 {
		return n.Address
	}
	return n.Hostname
}

// BindPropagation is bind propagation option for Docker
// https://docs.docker.com/storage/bind-mounts/#configure-bind-propagation
type BindPropagation string

// Bind propagation definitions
const (
	PropagationShared   = BindPropagation("shared")
	PropagationSlave    = BindPropagation("slave")
	PropagationPrivate  = BindPropagation("private")
	PropagationRShared  = BindPropagation("rshared")
	PropagationRSlave   = BindPropagation("rslave")
	PropagationRPrivate = BindPropagation("rprivate")
)

func (p BindPropagation) String() string {
	return string(p)
}

// SELinuxLabel is selinux label of the host file or directory
// https://docs.docker.com/storage/bind-mounts/#configure-the-selinux-label
type SELinuxLabel string

// SELinux Label definitions
const (
	LabelShared  = SELinuxLabel("z")
	LabelPrivate = SELinuxLabel("Z")
)

func (l SELinuxLabel) String() string {
	return string(l)
}

// Mount is volume mount information
type Mount struct {
	Source      string          `json:"source"        yaml:"source"`
	Destination string          `json:"destination"   yaml:"destination"`
	ReadOnly    bool            `json:"read_only"     yaml:"read_only"`
	Propagation BindPropagation `json:"propagation"   yaml:"propagation"`
	Label       SELinuxLabel    `json:"selinux_label" yaml:"selinux_label"`
}

// Equal returns true if the mount is equals to other one, otherwise return false
func (m Mount) Equal(o Mount) bool {
	return m.Source == o.Source && m.Destination == o.Destination && m.ReadOnly == o.ReadOnly
}

// ServiceParams is a common set of extra parameters for k8s components.
type ServiceParams struct {
	ExtraArguments []string          `json:"extra_args"  yaml:"extra_args"`
	ExtraBinds     []Mount           `json:"extra_binds" yaml:"extra_binds"`
	ExtraEnvvar    map[string]string `json:"extra_env"   yaml:"extra_env"`
}

// Equal returns true if the services params is equals to other one, otherwise return false
func (s ServiceParams) Equal(o ServiceParams) bool {
	return compareStrings(s.ExtraArguments, o.ExtraArguments) &&
		compareMounts(s.ExtraBinds, o.ExtraBinds) &&
		compareStringMap(s.ExtraEnvvar, o.ExtraEnvvar)
}

// EtcdParams is a set of extra parameters for etcd.
type EtcdParams struct {
	ServiceParams `yaml:",inline"`
	VolumeName    string `json:"volume_name" yaml:"volume_name"`
}

// KubeletParams is a set of extra parameters for kubelet.
type KubeletParams struct {
	ServiceParams `yaml:",inline"`
	Domain        string         `json:"domain"      yaml:"domain"`
	AllowSwap     bool           `json:"allow_swap"  yaml:"allow_swap"`
	BootTaints    []corev1.Taint `json:"boot_taints"   yaml:"boot_taints"`
}

// EtcdBackup is a set of configurations for etcdbackup.
type EtcdBackup struct {
	Enabled  bool   `json:"enabled"  yaml:"enabled"`
	PVCName  string `json:"pvc_name" yaml:"pvc_name"`
	Schedule string `json:"schedule" yaml:"schedule"`
	Rotate   int    `json:"rotate,omitempty" yaml:"rotate,omitempty"`
}

// Options is a set of optional parameters for k8s components.
type Options struct {
	Etcd              EtcdParams    `json:"etcd"                    yaml:"etcd"`
	Rivers            ServiceParams `json:"rivers"                  yaml:"rivers"`
	APIServer         ServiceParams `json:"kube-api"                yaml:"kube-api"`
	ControllerManager ServiceParams `json:"kube-controller-manager" yaml:"kube-controller-manager"`
	Scheduler         ServiceParams `json:"kube-scheduler"          yaml:"kube-scheduler"`
	Proxy             ServiceParams `json:"kube-proxy"              yaml:"kube-proxy"`
	Kubelet           KubeletParams `json:"kubelet"                 yaml:"kubelet"`
}

// Cluster is a set of configurations for a etcd/Kubernetes cluster.
type Cluster struct {
	Name          string     `json:"name"           yaml:"name"`
	Nodes         []*Node    `json:"nodes"          yaml:"nodes"`
	ServiceSubnet string     `json:"service_subnet" yaml:"service_subnet"`
	PodSubnet     string     `json:"pod_subnet"     yaml:"pod_subnet"`
	DNSServers    []string   `json:"dns_servers"    yaml:"dns_servers"`
	DNSService    string     `json:"dns_service"    yaml:"dns_service"`
	EtcdBackup    EtcdBackup `json:"etcd_backup"    yaml:"etcd_backup"`
	Options       Options    `json:"options"        yaml:"options"`
}

// Validate validates the cluster definition.
func (c *Cluster) Validate() error {
	if len(c.Name) == 0 {
		return errors.New("cluster name is empty")
	}

	_, _, err := net.ParseCIDR(c.ServiceSubnet)
	if err != nil {
		return err
	}
	_, _, err = net.ParseCIDR(c.PodSubnet)
	if err != nil {
		return err
	}

	fldPath := field.NewPath("nodes")
	for i, n := range c.Nodes {
		err := c.validateNode(n, fldPath.Index(i))
		if err != nil {
			return err
		}
	}

	for _, a := range c.DNSServers {
		if net.ParseIP(a) == nil {
			return errors.New("invalid IP address: " + a)
		}
	}

	if len(c.DNSService) > 0 {
		fields := strings.Split(c.DNSService, "/")
		if len(fields) != 2 {
			return errors.New("invalid DNS service (no namespace?): " + c.DNSService)
		}
	}

	err = validateEtcdBackup(c.EtcdBackup)
	if err != nil {
		return err
	}

	err = validateOptions(c.Options)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cluster) validateNode(n *Node, fldPath *field.Path) error {
	if net.ParseIP(n.Address) == nil {
		return errors.New("invalid IP address: " + n.Address)
	}
	if len(n.User) == 0 {
		return errors.New("user name is empty")
	}

	if err := validateNodeLabels(n, fldPath.Child("labels")); err != nil {
		return err
	}
	if err := validateNodeAnnotations(n, fldPath.Child("annotations")); err != nil {
		return err
	}
	if err := validateNodeTaints(n, fldPath.Child("taints")); err != nil {
		return err
	}
	return nil
}

// validateNodeLabels validates label names and values with
// rules described in:
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
func validateNodeLabels(n *Node, fldPath *field.Path) error {
	el := v1validation.ValidateLabels(n.Labels, fldPath)
	if len(el) == 0 {
		return nil
	}
	return el.ToAggregate()
}

// validateNodeAnnotations validates annotation names.
// The validation logic references:
// https://github.com/kubernetes/apimachinery/blob/60666be32c5de527b69dabe8e4400b4f0aa897de/pkg/api/validation/objectmeta.go#L50
func validateNodeAnnotations(n *Node, fldPath *field.Path) error {
	for k := range n.Annotations {
		msgs := validation.IsQualifiedName(strings.ToLower(k))
		if len(msgs) > 0 {
			el := make(field.ErrorList, len(msgs))
			for i, msg := range msgs {
				el[i] = field.Invalid(fldPath, k, msg)
			}
			return el.ToAggregate()
		}
	}
	return nil
}

// validateNodeTaints validates taint names, values, and effects.
func validateNodeTaints(n *Node, fldPath *field.Path) error {
	for i, taint := range n.Taints {
		err := validateTaint(taint, fldPath.Index(i))
		if err != nil {
			return err
		}
	}
	return nil
}

// validateTaint validates a taint name, value, and effect.
// The validation logic references:
// https://github.com/kubernetes/kubernetes/blob/7cbb9995189c5ecc8182da29cd0e30188c911401/pkg/apis/core/validation/validation.go#L4105
func validateTaint(taint corev1.Taint, fldPath *field.Path) error {
	el := v1validation.ValidateLabelName(taint.Key, fldPath.Child("key"))
	if msgs := validation.IsValidLabelValue(taint.Value); len(msgs) > 0 {
		el = append(el, field.Invalid(fldPath.Child("value"), taint.Value, strings.Join(msgs, ";")))
	}
	switch taint.Effect {
	case corev1.TaintEffectNoSchedule:
	case corev1.TaintEffectPreferNoSchedule:
	case corev1.TaintEffectNoExecute:
	default:
		el = append(el, field.Invalid(fldPath.Child("effect"), string(taint.Effect), "invalid effect"))
	}
	if len(el) > 0 {
		return el.ToAggregate()
	}
	return nil
}

// ControlPlanes returns control plane []*Node
func ControlPlanes(nodes []*Node) []*Node {
	return filterNodes(nodes, func(n *Node) bool {
		return n.ControlPlane
	})
}

func filterNodes(nodes []*Node, f func(n *Node) bool) []*Node {
	var filtered []*Node
	for _, n := range nodes {
		if f(n) {
			filtered = append(filtered, n)
		}
	}
	return filtered
}

func validateEtcdBackup(etcdBackup EtcdBackup) error {
	if etcdBackup.Enabled == false {
		return nil
	}
	if len(etcdBackup.PVCName) == 0 {
		return errors.New("pvc_name is empty")
	}
	if len(etcdBackup.Schedule) == 0 {
		return errors.New("schedule is empty")
	}
	return nil
}

func validateOptions(opts Options) error {
	v := func(binds []Mount) error {
		for _, m := range binds {
			if !filepath.IsAbs(m.Source) {
				return errors.New("source path must be absolute: " + m.Source)
			}
			if !filepath.IsAbs(m.Destination) {
				return errors.New("destination path must be absolute: " + m.Destination)
			}
		}
		return nil
	}

	err := v(opts.Etcd.ExtraBinds)
	if err != nil {
		return err
	}
	err = v(opts.APIServer.ExtraBinds)
	if err != nil {
		return err
	}
	err = v(opts.ControllerManager.ExtraBinds)
	if err != nil {
		return err
	}
	err = v(opts.Scheduler.ExtraBinds)
	if err != nil {
		return err
	}
	err = v(opts.Proxy.ExtraBinds)
	if err != nil {
		return err
	}
	err = v(opts.Kubelet.ExtraBinds)
	if err != nil {
		return err
	}

	fldPath := field.NewPath("options", "kubelet")
	if len(opts.Kubelet.Domain) > 0 {
		msgs := validation.IsDNS1123Subdomain(opts.Kubelet.Domain)
		if len(msgs) > 0 {
			return field.Invalid(fldPath.Child("domain"),
				opts.Kubelet.Domain, strings.Join(msgs, ";"))
		}
	}

	fldPath = fldPath.Child("boot_taints")
	for i, taint := range opts.Kubelet.BootTaints {
		err := validateTaint(taint, fldPath.Index(i))
		if err != nil {
			return err
		}
	}

	return nil
}
