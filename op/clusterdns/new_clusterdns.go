package clusterdns

import (
	"bytes"
	"context"
	"strings"
	"text/template"

	"github.com/cybozu-go/cke"
	"github.com/cybozu-go/cke/op"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// CoreDNSTemplateVersion is the version of CoreDNS template
const CoreDNSTemplateVersion = "2"

// retrieved from https://github.com/kelseyhightower/kubernetes-the-hard-way
var deploymentText = `
metadata:
  name: cluster-dns
  namespace: kube-system
  annotations:
    cke.cybozu.com/image: ` + cke.CoreDNSImage.Name() + `
    cke.cybozu.com/template-version: ` + CoreDNSTemplateVersion + `
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      cke.cybozu.com/appname: cluster-dns
  template:
    metadata:
      labels:
        cke.cybozu.com/appname: cluster-dns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: cluster-dns
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      containers:
      - name: coredns
        image: ` + cke.CoreDNSImage.Name() + `
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: ` + op.ClusterDNSAppName + `
            items:
            - key: Corefile
              path: Corefile
`

type createServiceAccountOp struct {
	apiserver *cke.Node
	finished  bool
}

// CreateServiceAccountOp returns an Operator to create serviceaccount for CoreDNS.
func CreateServiceAccountOp(apiserver *cke.Node) cke.Operator {
	return &createServiceAccountOp{
		apiserver: apiserver,
	}
}

func (o *createServiceAccountOp) Name() string {
	return "create-cluster-dns-serviceaccount"
}

func (o *createServiceAccountOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createServiceAccountCommand{o.apiserver}
}

type createServiceAccountCommand struct {
	apiserver *cke.Node
}

func (c createServiceAccountCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// ServiceAccount
	accounts := cs.CoreV1().ServiceAccounts("kube-system")
	_, err = accounts.Get(op.ClusterDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err = accounts.Create(&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      op.ClusterDNSAppName,
				Namespace: "kube-system",
			},
		})
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

func (c createServiceAccountCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createServiceAccountCommand",
		Target: "kube-system",
	}
}

type createRBACRoleOp struct {
	apiserver *cke.Node
	finished  bool
}

// CreateRBACRoleOp returns an Operator to create RBAC Role for CoreDNS.
func CreateRBACRoleOp(apiserver *cke.Node) cke.Operator {
	return &createRBACRoleOp{
		apiserver: apiserver,
	}
}

func (o *createRBACRoleOp) Name() string {
	return "create-cluster-dns-rbac-role"
}

func (o *createRBACRoleOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createRBACRoleCommand{o.apiserver}
}

type createRBACRoleCommand struct {
	apiserver *cke.Node
}

func (c createRBACRoleCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// ClusterRole
	clusterRoles := cs.RbacV1().ClusterRoles()
	_, err = clusterRoles.Get(op.ClusterDNSRBACRoleName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err = clusterRoles.Create(&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: op.ClusterDNSRBACRoleName,
				Labels: map[string]string{
					"kubernetes.io/bootstrapping": "rbac-defaults",
				},
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"endpoints",
						"services",
						"pods",
						"namespaces",
					},
					Verbs: []string{
						"list",
						"watch",
					},
				},
			},
		})
		if err != nil {
			return err
		}
	default:
		return err
	}
	return nil
}

func (c createRBACRoleCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createRBACRoleCommand",
		Target: "kube-system",
	}
}

type createRBACRoleBindingOp struct {
	apiserver  *cke.Node
	domain     string
	dnsServers []string
	finished   bool
}

// CreateRBACRoleBindingOp returns an Operator to create RBAC Role Binding for CoreDNS.
func CreateRBACRoleBindingOp(apiserver *cke.Node) cke.Operator {
	return &createRBACRoleBindingOp{
		apiserver: apiserver,
	}
}

func (o *createRBACRoleBindingOp) Name() string {
	return "create-cluster-dns-rbac-role-binding"
}

func (o *createRBACRoleBindingOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createRBACRoleBindingCommand{o.apiserver}
}

type createRBACRoleBindingCommand struct {
	apiserver *cke.Node
}

func (c createRBACRoleBindingCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}
	// ClusterRoleBinding
	clusterRoleBindings := cs.RbacV1().ClusterRoleBindings()
	_, err = clusterRoleBindings.Get(op.ClusterDNSRBACRoleName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err = clusterRoleBindings.Create(&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: op.ClusterDNSRBACRoleName,
				Labels: map[string]string{
					"kubernetes.io/bootstrapping": "rbac-defaults",
				},
				Annotations: map[string]string{
					// turn on auto-reconciliation
					// https://kubernetes.io/docs/reference/access-authn-authz/rbac/#auto-reconciliation
					rbacv1.AutoUpdateAnnotationKey: "true",
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     op.ClusterDNSRBACRoleName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      op.ClusterDNSAppName,
					Namespace: "kube-system",
				},
			},
		})
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

func (c createRBACRoleBindingCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createRBACRoleBindingCommand",
		Target: "kube-system",
	}
}

type createConfigMapOp struct {
	apiserver  *cke.Node
	domain     string
	dnsServers []string
	finished   bool
}

// CreateConfigMapOp returns an Operator to create ConfigMap for CoreDNS.
func CreateConfigMapOp(apiserver *cke.Node, domain string, dnsServers []string) cke.Operator {
	return &createConfigMapOp{
		apiserver:  apiserver,
		domain:     domain,
		dnsServers: dnsServers,
	}
}

func (o *createConfigMapOp) Name() string {
	return "create-cluster-dns-configmap"
}

func (o *createConfigMapOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createConfigMapCommand{o.apiserver, o.domain, o.dnsServers}
}

func (c createConfigMapCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createConfigMapCommand",
		Target: "kube-system",
	}
}

type createConfigMapCommand struct {
	apiserver  *cke.Node
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
	_, err = configs.Get(op.ClusterDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err = configs.Create(ConfigMap(c.domain, c.dnsServers))
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

type createDeploymentOp struct {
	apiserver *cke.Node
	finished  bool
}

// CreateDeploymentOp returns an Operator to create deployment of CoreDNS.
func CreateDeploymentOp(apiserver *cke.Node) cke.Operator {
	return &createDeploymentOp{
		apiserver: apiserver,
	}
}

func (o *createDeploymentOp) Name() string {
	return "create-cluster-dns-deployment"
}

func (o *createDeploymentOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createDeploymentCommand{o.apiserver}
}

type createDeploymentCommand struct {
	apiserver *cke.Node
}

func (c createDeploymentCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// Deployment
	deployments := cs.AppsV1().Deployments("kube-system")
	_, err = deployments.Get(op.ClusterDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		deployment := new(appsv1.Deployment)
		err = yaml.NewYAMLToJSONDecoder(strings.NewReader(deploymentText)).Decode(deployment)
		if err != nil {
			return err
		}
		_, err = deployments.Create(deployment)
		if err != nil {
			return err
		}
	default:
		return err
	}
	return nil
}

func (c createDeploymentCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createDeploymentCommand",
		Target: "kube-system",
	}
}

type kubeCreateServiceOp struct {
	apiserver *cke.Node
	finished  bool
}

// CreateOp returns an Operator to create cluster resolver.
func CreateOp(apiserver *cke.Node) cke.Operator {
	return &kubeCreateServiceOp{
		apiserver: apiserver,
	}
}

func (o *kubeCreateServiceOp) Name() string {
	return "create-cluster-dns-service"
}

func (o *kubeCreateServiceOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return createServiceCommand{o.apiserver}
}

type createServiceCommand struct {
	apiserver *cke.Node
}

func (c createServiceCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// Service
	services := cs.CoreV1().Services("kube-system")
	_, err = services.Get(op.ClusterDNSAppName, metav1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err = services.Create(getService())
		if err != nil {
			return err
		}
	default:
		return err
	}

	return nil
}

func (c createServiceCommand) Command() cke.Command {
	return cke.Command{
		Name:   "createServiceCommand",
		Target: "kube-system",
	}
}

type updateConfigMapOp struct {
	apiserver *cke.Node
	configmap *corev1.ConfigMap
	finished  bool
}

// UpdateConfigMapOp returns an Operator to update ConfigMap for CoreDNS.
func UpdateConfigMapOp(apiserver *cke.Node, configmap *corev1.ConfigMap) cke.Operator {
	return &updateConfigMapOp{
		apiserver: apiserver,
		configmap: configmap,
	}
}

func (o *updateConfigMapOp) Name() string {
	return "update-cluster-dns-configmap"
}

func (o *updateConfigMapOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return updateConfigMapCommand{o.apiserver, o.configmap}
}

type updateConfigMapCommand struct {
	apiserver *cke.Node
	configmap *corev1.ConfigMap
}

func (c updateConfigMapCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// ConfigMap
	configs := cs.CoreV1().ConfigMaps("kube-system")
	_, err = configs.Update(c.configmap)
	return err
}

func (c updateConfigMapCommand) Command() cke.Command {
	return cke.Command{
		Name:   "updateConfigMapCommand",
		Target: "kube-system",
	}
}

type updateDeploymentOp struct {
	apiserver *cke.Node
	finished  bool
}

// UpdateDeploymentOp returns an Operator to update deployment of CoreDNS.
func UpdateDeploymentOp(apiserver *cke.Node) cke.Operator {
	return &updateDeploymentOp{
		apiserver: apiserver,
	}
}

func (o *updateDeploymentOp) Name() string {
	return "update-cluster-dns-deployment"
}

func (o *updateDeploymentOp) NextCommand() cke.Commander {
	if o.finished {
		return nil
	}
	o.finished = true
	return updateDeploymentCommand{o.apiserver}
}

type updateDeploymentCommand struct {
	apiserver *cke.Node
}

func (c updateDeploymentCommand) Run(ctx context.Context, inf cke.Infrastructure) error {
	cs, err := inf.K8sClient(ctx, c.apiserver)
	if err != nil {
		return err
	}

	// Deployment
	deployments := cs.AppsV1().Deployments("kube-system")
	deployment := new(appsv1.Deployment)
	err = yaml.NewYAMLToJSONDecoder(strings.NewReader(deploymentText)).Decode(deployment)
	if err != nil {
		return err
	}
	_, err = deployments.Update(deployment)
	return err
}

func (c updateDeploymentCommand) Command() cke.Command {
	return cke.Command{
		Name:   "updateDeploymentCommand",
		Target: "kube-system",
	}
}

var clusterDNSTemplate = template.Must(template.New("").Parse(`.:53 {
    errors
    health
    log
    kubernetes {{ .Domain }} in-addr.arpa ip6.arpa {
      pods verified
{{- if .Upstreams }}
      upstream
      fallthrough in-addr.arpa ip6.arpa
{{- end }}
    }
{{- if .Upstreams }}
    proxy . {{ .Upstreams }}
{{- end }}
    cache 30
    reload
    loadbalance
}
`))

// ConfigMap returns ConfigMap for CoreDNS
func ConfigMap(domain string, dnsServers []string) *corev1.ConfigMap {
	buf := new(bytes.Buffer)
	err := clusterDNSTemplate.Execute(buf, struct {
		Domain    string
		Upstreams string
	}{
		Domain:    domain,
		Upstreams: strings.Join(dnsServers, " "),
	})
	if err != nil {
		panic(err)
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      op.ClusterDNSAppName,
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"Corefile": buf.String(),
		},
	}
}

func getService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      op.ClusterDNSAppName,
			Namespace: "kube-system",
			Labels: map[string]string{
				op.CKELabelAppName: op.ClusterDNSAppName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				op.CKELabelAppName: op.ClusterDNSAppName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "dns",
					Port:     53,
					Protocol: corev1.ProtocolUDP,
				},
				{
					Name:     "dns-tcp",
					Port:     53,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}
