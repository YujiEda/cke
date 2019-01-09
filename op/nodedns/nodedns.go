package nodedns

import (
	"bytes"
	"context"
	"strings"
	"text/template"

	"github.com/cybozu-go/cke"
	"github.com/cybozu-go/cke/op"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type unboundConfigTemplate struct {
	Domain    string
	ClusterIP string
	Upstreams []string
}

const unboundConfigTemplateText = `
server:
  do-daemonize: no
  interface: 0.0.0.0
  interface-automatic: yes
  access-control: 0.0.0.0/0 allow
  chroot: ""
  username: ""
  directory: "/etc/unbound"
  logfile: ""
  use-syslog: no
  log-time-ascii: yes
  log-queries: yes
  log-replies: yes
  log-local-actions: yes
  log-servfail: yes
  rrset-roundrobin: yes
  pidfile: "/tmp/unbound.pid"
  infra-host-ttl: 60
  prefetch: yes
remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
  control-use-cert: no
stub-zone:
  name: "{{ .Domain }}"
  stub-addr: {{ .ClusterIP }}
forward-zone:
  name: "in-addr.arpa."
  forward-addr: {{ .ClusterIP }}
forward-zone:
  name: "ip6.arpa."
  forward-addr: {{ .ClusterIP }}
{{- if .Upstreams }}
forward-zone:
  name: "."
  {{- range .Upstreams }}
  forward-addr: {{ . }}
  {{- end }}
{{- end }}
`

// UnboundTemplateVersion is the version of unbound template
const UnboundTemplateVersion = "1"

var unboundDaemonSetText = `
metadata:
  name: node-dns
  namespace: kube-system
  annotations:
    cke.cybozu.com/image: ` + cke.UnboundImage.Name() + `
    cke.cybozu.com/template-version: ` + UnboundTemplateVersion + `
spec:
  selector:
    matchLabels:
      cke.cybozu.com/appname: node-dns
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        cke.cybozu.com/appname: node-dns
    spec:
      priorityClassName: system-node-critical
      nodeSelector:
        beta.kubernetes.io/os: linux
      hostNetwork: true
      tolerations:
        # Make sure unbound gets scheduled on all nodes.
        - effect: NoSchedule
          operator: Exists
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      terminationGracePeriodSeconds: 0
      containers:
        - name: unbound
          image: ` + cke.UnboundImage.Name() + `
          args:
            - -c
            - /etc/unbound/unbound.conf
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              add:
              - NET_BIND_SERVICE
              drop:
              - all
            readOnlyRootFilesystem: true
          livenessProbe:
            tcpSocket:
              port: 53
              host: localhost
            periodSeconds: 1
            initialDelaySeconds: 1
            failureThreshold: 6
          volumeMounts:
            - name: config-volume
              mountPath: /etc/unbound
        - name: reload
          image: ` + cke.UnboundImage.Name() + `
          command:
          - /usr/local/bin/reload-unbound
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
              - all
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: config-volume
              mountPath: /etc/unbound
      volumes:
        - name: config-volume
          configMap:
            name: node-dns
            items:
            - key: unbound.conf
              path: unbound.conf
`

type createConfigMapOp struct {
	apiserver  *cke.Node
	clusterIP  string
	domain     string
	dnsServers []string
	finished   bool
}

// CreateConfigMapOp returns an Operator to create ConfigMap for unbound daemonset.
func CreateConfigMapOp(apiserver *cke.Node, clusterIP, domain string, dnsServers []string) cke.Operator {
	return &createConfigMapOp{
		apiserver:  apiserver,
		clusterIP:  clusterIP,
		domain:     domain,
		dnsServers: dnsServers,
	}
}

func (o *createConfigMapOp) Name() string {
	return "create-node-dns-configmap"
}

func (o *createConfigMapOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createConfigMapCommand{o.apiserver, o.clusterIP, o.domain, o.dnsServers}
}

type createConfigMapCommand struct {
	apiserver  *cke.Node
	clusterIP  string
	domain     string
	dnsServers []string
}

func (c createConfigMapCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// ConfigMap
	configs := cs.CoreV1().ConfigMaps("kube-system")
	_, err = configs.Get(op.NodeDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		configMap := ConfigMap(c.clusterIP, c.domain, c.dnsServers)
		_, err = configs.Create(configMap)
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

func (c createConfigMapCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createConfigMapCommand",
		Target: "kube-system",
	}
}

type createDaemonSetOp struct {
	apiserver *cke.Node
	finished  bool
}

// CreateDaemonSetOp returns an Operator to create unbound daemonset.
func CreateDaemonSetOp(apiserver *cke.Node) cke.Operator {
	return &createDaemonSetOp{
		apiserver: apiserver,
	}
}

func (o *createDaemonSetOp) Name() string {
	return "create-node-dns-daemonset"
}

func (o *createDaemonSetOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createDaemonSetCommand{o.apiserver}
}

type createDaemonSetCommand struct {
	apiserver *cke.Node
}

func (c createDaemonSetCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// DaemonSet
	daemonSets := cs.AppsV1().DaemonSets("kube-system")
	_, err = daemonSets.Get(op.NodeDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		daemonSet := new(appsv1.DaemonSet)
		err = yaml.NewYAMLToJSONDecoder(strings.NewReader(unboundDaemonSetText)).Decode(daemonSet)
		if err != nil {
			return err
		}
		_, err = daemonSets.Create(daemonSet)
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

func (c createDaemonSetCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createDaemonSetCommand",
		Target: "kube-system",
	}
}

type updateConfigMapOp struct {
	apiserver *cke.Node
	configMap *corev1.ConfigMap
	finished  bool
}

// UpdateConfigMapOp returns an Operator to update unbound as Node local resolver.
func UpdateConfigMapOp(apiserver *cke.Node, configMap *corev1.ConfigMap) cke.Operator {
	return &updateConfigMapOp{
		apiserver: apiserver,
		configMap: configMap,
	}
}

func (o *updateConfigMapOp) Name() string {
	return "update-node-dns-configmap"
}

func (o *updateConfigMapOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return updateConfigMapCommand{o.apiserver, o.configMap}
}

type updateConfigMapCommand struct {
	apiserver *cke.Node
	configMap *corev1.ConfigMap
}

func (c updateConfigMapCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	configs := cs.CoreV1().ConfigMaps("kube-system")
	_, err = configs.Update(c.configMap)
	return err
}

func (c updateConfigMapCommand) Command() cke.Command {
	return cke.Command{
		Name:   "updateConfigMapCommand",
		Target: "kube-system",
	}
}

// ConfigMap returns ConfigMap for unbound daemonset
func ConfigMap(clusterIP, domain string, dnsServers []string) *corev1.ConfigMap {
	var confTempl unboundConfigTemplate
	confTempl.Domain = domain
	confTempl.ClusterIP = clusterIP
	confTempl.Upstreams = dnsServers

	tmpl := template.Must(template.New("").Parse(unboundConfigTemplateText))
	unboundConf := new(bytes.Buffer)
	err := tmpl.Execute(unboundConf, confTempl)
	if err != nil {
		panic(err)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      op.NodeDNSAppName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"unbound.conf": unboundConf.String(),
		},
	}
}

type updateDaemonSetOp struct {
	apiserver *cke.Node
	finished  bool
}

// UpdateDaemonSetOp returns an Operator to update unbound daemonset.
func UpdateDaemonSetOp(apiserver *cke.Node) cke.Operator {
	return &updateDaemonSetOp{
		apiserver: apiserver,
	}
}

func (o *updateDaemonSetOp) Name() string {
	return "update-node-dns-daemonset"
}

func (o *updateDaemonSetOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return updateDaemonSetCommand{o.apiserver}
}

type updateDaemonSetCommand struct {
	apiserver *cke.Node
}

func (c updateDaemonSetCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	daemonSet := new(appsv1.DaemonSet)
	err = yaml.NewYAMLToJSONDecoder(strings.NewReader(unboundDaemonSetText)).Decode(daemonSet)
	if err != nil {
		return err
	}

	_, err = cs.AppsV1().DaemonSets("kube-system").Update(daemonSet)
	return err
}

func (c updateDaemonSetCommand) Command() cke.Command {
	return cke.Command{
		Name:   "updateNodeDNSDaemonSet",
		Target: "kube-system/node-dns",
	}
}
