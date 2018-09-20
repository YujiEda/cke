package cke

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cybozu-go/cmd"
	yaml "gopkg.in/yaml.v2"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// Command represents some command
type Command struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// String implements fmt.Stringer
func (c Command) String() string {
	if len(c.Detail) > 0 {
		return fmt.Sprintf("%s %s: %s", c.Name, c.Target, c.Detail)
	}
	return fmt.Sprintf("%s %s", c.Name, c.Target)
}

// Commander is a single step to proceed an operation
type Commander interface {
	// Run executes the command
	Run(ctx context.Context, inf Infrastructure) error
	// Command returns the command information
	Command() Command
}

type makeDirsCommand struct {
	nodes []*Node
	dirs  []string
}

func (c makeDirsCommand) Run(ctx context.Context, inf Infrastructure) error {
	bindMap := make(map[string]Mount)
	dests := make([]string, len(c.dirs))
	for i, d := range c.dirs {
		dests[i] = filepath.Join("/mnt", d)

		parentDir := filepath.Dir(d)
		if _, ok := bindMap[parentDir]; ok {
			continue
		}
		bindMap[parentDir] = Mount{
			Source:      parentDir,
			Destination: filepath.Join("/mnt", parentDir),
			Label:       LabelPrivate,
		}
	}
	binds := make([]Mount, 0, len(bindMap))
	for _, m := range bindMap {
		binds = append(binds, m)
	}

	arg := "/usr/local/cke-tools/bin/make_directories " + strings.Join(dests, " ")

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			return ce.Run(ToolsImage, binds, arg)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c makeDirsCommand) Command() Command {
	return Command{
		Name:   "make-dirs",
		Target: strings.Join(c.dirs, " "),
	}
}

type fileData struct {
	name    string
	dataMap map[string][]byte
}

type makeFilesCommand struct {
	nodes []*Node
	files []fileData
}

func (c *makeFilesCommand) AddFile(ctx context.Context, name string,
	f func(context.Context, *Node) ([]byte, error)) error {
	var mu sync.Mutex
	dataMap := make(map[string][]byte)

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		n := n
		env.Go(func(ctx context.Context) error {
			data, err := f(ctx, n)
			if err != nil {
				return err
			}
			mu.Lock()
			dataMap[n.Address] = data
			mu.Unlock()
			return nil
		})
	}
	env.Stop()
	err := env.Wait()
	if err != nil {
		return err
	}

	c.files = append(c.files, fileData{name, dataMap})
	return nil
}

func (c *makeFilesCommand) AddKeyPair(ctx context.Context, name string,
	f func(context.Context, *Node) (cert, key []byte, err error)) error {
	var mu sync.Mutex
	certMap := make(map[string][]byte)
	keyMap := make(map[string][]byte)

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		n := n
		env.Go(func(ctx context.Context) error {
			certData, keyData, err := f(ctx, n)
			if err != nil {
				return err
			}
			mu.Lock()
			certMap[n.Address] = certData
			keyMap[n.Address] = keyData
			mu.Unlock()
			return nil
		})
	}
	env.Stop()
	err := env.Wait()
	if err != nil {
		return err
	}

	c.files = append(c.files, fileData{name + ".crt", certMap})
	c.files = append(c.files, fileData{name + ".key", keyMap})
	return nil
}

func (c *makeFilesCommand) Run(ctx context.Context, inf Infrastructure) error {
	bindMap := make(map[string]Mount)
	for _, f := range c.files {
		parentDir := filepath.Dir(f.name)
		if _, ok := bindMap[parentDir]; ok {
			continue
		}
		bindMap[parentDir] = Mount{
			Source:      parentDir,
			Destination: filepath.Join("/mnt", parentDir),
			Label:       LabelPrivate,
		}
	}
	binds := make([]Mount, 0, len(bindMap))
	for _, m := range bindMap {
		binds = append(binds, m)
	}

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		n := n
		env.Go(func(ctx context.Context) error {
			buf := new(bytes.Buffer)
			tw := tar.NewWriter(buf)
			for _, f := range c.files {
				data := f.dataMap[n.Address]
				hdr := &tar.Header{
					Name: f.name,
					Mode: 0644,
					Size: int64(len(data)),
				}
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
				if _, err := tw.Write(data); err != nil {
					return err
				}
			}
			if err := tw.Close(); err != nil {
				return err
			}
			data := buf.String()

			arg := "/usr/local/cke-tools/bin/write_files /mnt"
			ce := Docker(inf.Agent(n.Address))
			return ce.RunWithInput(ToolsImage, binds, arg, data)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c *makeFilesCommand) Command() Command {
	fileNames := make([]string, len(c.files))
	for i, f := range c.files {
		fileNames[i] = f.name
	}
	return Command{
		Name:   "make-files",
		Target: strings.Join(fileNames, ","),
	}
}

type removeFileCommand struct {
	nodes  []*Node
	target string
}

func (c removeFileCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	dir := filepath.Dir(c.target)
	binds := []Mount{{
		Source:      dir,
		Destination: filepath.Join("/mnt", dir),
	}}
	command := "rm -f " + filepath.Join("/mnt", c.target)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			return ce.Run(ToolsImage, binds, command)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c removeFileCommand) Command() Command {
	return Command{
		Name:   "rm",
		Target: c.target,
	}
}

type imagePullCommand struct {
	nodes []*Node
	img   Image
}

func (c imagePullCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			return ce.PullImage(c.img)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c imagePullCommand) Command() Command {
	return Command{
		Name:   "image-pull",
		Target: c.img.Name(),
	}
}

type volumeCreateCommand struct {
	nodes   []*Node
	volname string
}

func (c volumeCreateCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			return ce.VolumeCreate(c.volname)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c volumeCreateCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "volume-create",
		Target: strings.Join(targets, ","),
		Detail: c.volname,
	}
}

type volumeRemoveCommand struct {
	nodes   []*Node
	volname string
}

func (c volumeRemoveCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			exists, err := ce.VolumeExists(c.volname)
			if err != nil {
				return err
			}
			if exists {
				return ce.VolumeRemove(c.volname)
			}
			return nil
		})
	}
	env.Stop()
	return env.Wait()
}

func (c volumeRemoveCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "volume-remove",
		Target: strings.Join(targets, ","),
		Detail: c.volname,
	}
}

type runContainerCommand struct {
	nodes     []*Node
	name      string
	img       Image
	opts      []string
	optsMap   map[string][]string
	params    ServiceParams
	paramsMap map[string]ServiceParams
	extra     ServiceParams
}

func (c runContainerCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		n := n
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			params, ok := c.paramsMap[n.Address]
			if !ok {
				params = c.params
			}
			opts, ok := c.optsMap[n.Address]
			if !ok {
				opts = c.opts
			}
			return ce.RunSystem(c.name, c.img, opts, params, c.extra)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c runContainerCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "run-container",
		Target: strings.Join(targets, ","),
		Detail: c.name,
	}
}

type stopContainerCommand struct {
	node *Node
	name string
}

func (c stopContainerCommand) Run(ctx context.Context, inf Infrastructure) error {
	ce := Docker(inf.Agent(c.node.Address))
	exists, err := ce.Exists(c.name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	err = ce.Stop(c.name)
	if err != nil {
		return err
	}
	// gofail: var dockerAfterContainerStop struct{}
	return ce.Remove(c.name)
}

func (c stopContainerCommand) Command() Command {
	return Command{
		Name:   "stop-container",
		Target: c.node.Address,
		Detail: c.name,
	}
}

type stopContainersCommand struct {
	nodes []*Node
	name  string
}

func (c stopContainersCommand) Run(ctx context.Context, inf Infrastructure) error {

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			exists, err := ce.Exists(c.name)
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			err = ce.Stop(c.name)
			if err != nil {
				return err
			}
			return ce.Remove(c.name)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c stopContainersCommand) Command() Command {
	addrs := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		addrs[i] = n.Address
	}
	return Command{
		Name:   "stop-containers",
		Target: strings.Join(addrs, ","),
		Detail: c.name,
	}
}

type prepareEtcdCertificatesCommand struct {
	makeFiles *makeFilesCommand
}

func (c prepareEtcdCertificatesCommand) Run(ctx context.Context, inf Infrastructure) error {
	f := func(ctx context.Context, n *Node) (cert, key []byte, err error) {
		c, k, e := EtcdCA{}.issueServerCert(ctx, inf, n)
		if e != nil {
			return nil, nil, e
		}
		return []byte(c), []byte(k), nil
	}
	err := c.makeFiles.AddKeyPair(ctx, EtcdPKIPath("server"), f)
	if err != nil {
		return err
	}

	f = func(ctx context.Context, n *Node) (cert, key []byte, err error) {
		c, k, e := EtcdCA{}.issuePeerCert(ctx, inf, n)
		if e != nil {
			return nil, nil, e
		}
		return []byte(c), []byte(k), nil
	}
	err = c.makeFiles.AddKeyPair(ctx, EtcdPKIPath("peer"), f)
	if err != nil {
		return err
	}

	peerCA, err := inf.Storage().GetCACertificate(ctx, "etcd-peer")
	if err != nil {
		return err
	}
	f2 := func(ctx context.Context, node *Node) ([]byte, error) {
		return []byte(peerCA), nil
	}
	err = c.makeFiles.AddFile(ctx, EtcdPKIPath("ca-peer.crt"), f2)
	if err != nil {
		return err
	}

	clientCA, err := inf.Storage().GetCACertificate(ctx, "etcd-client")
	if err != nil {
		return err
	}
	f2 = func(ctx context.Context, node *Node) ([]byte, error) {
		return []byte(clientCA), nil
	}
	err = c.makeFiles.AddFile(ctx, EtcdPKIPath("ca-client.crt"), f2)
	if err != nil {
		return err
	}
	return nil
}

func (c prepareEtcdCertificatesCommand) Command() Command {
	targets := make([]string, len(c.makeFiles.nodes))
	for i, n := range c.makeFiles.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "prepare-etcd-certificates",
		Target: strings.Join(targets, ","),
	}
}

type setupAPIServerCertificatesCommand struct {
	makeFiles *makeFilesCommand
}

func (c setupAPIServerCertificatesCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, node := range c.nodes {
		n := node
		env.Go(func(ctx context.Context) error {
			return EtcdCA{}.issueForAPIServer(ctx, inf, n)
		})
	}
	env.Stop()
	return env.Wait()
	env := cmd.NewEnvironment(ctx)
	for _, node := range c.nodes {
		n := node
		env.Go(func(ctx context.Context) error {
			return KubernetesCA{}.setup(ctx, inf, n)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c setupAPIServerCertificatesCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "setup-apiserver-certificates",
		Target: strings.Join(targets, ","),
	}
}

type makeControllerManagerKubeconfigCommand struct {
	cluster   string
	makeFiles *makeFilesCommand
}

func (c makeControllerManagerKubeconfigCommand) Run(ctx context.Context, inf Infrastructure) error {
	const path = "/etc/kubernetes/controller-manager/kubeconfig"

	ca, err := inf.Storage().GetCACertificate(ctx, "kubernetes")
	if err != nil {
		return err
	}
	crt, key, err := KubernetesCA{}.issueForControllerManager(ctx, inf)
	if err != nil {
		return err
	}
	cfg := controllerManagerKubeconfig(c.cluster, ca, crt, key)
	src, err := clientcmd.Write(*cfg)
	if err != nil {
		return err
	}
	return makeFilesCommand{c.nodes, string(src), path}.Run(ctx, inf)
}

func (c makeControllerManagerKubeconfigCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "make-controller-manager-kubeconfig",
		Target: strings.Join(targets, ","),
	}
}

type makeSchedulerKubeconfigCommand struct {
	cluster   string
	makeFiles *makeFilesCommand
}

func (c makeSchedulerKubeconfigCommand) Run(ctx context.Context, inf Infrastructure) error {
	const path = "/etc/kubernetes/scheduler/kubeconfig"

	ca, err := inf.Storage().GetCACertificate(ctx, "kubernetes")
	if err != nil {
		return err
	}
	crt, key, err := KubernetesCA{}.issueForScheduler(ctx, inf)
	if err != nil {
		return err
	}
	cfg := schedulerKubeconfig(c.cluster, ca, crt, key)
	src, err := clientcmd.Write(*cfg)
	if err != nil {
		return err
	}
	return makeFilesCommand{c.nodes, string(src), path}.Run(ctx, inf)
}

func (c makeSchedulerKubeconfigCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "make-scheduler-kubeconfig",
		Target: strings.Join(targets, ","),
	}
}

type makeProxyKubeconfigCommand struct {
	nodes   []*Node
	cluster string
}

func (c makeProxyKubeconfigCommand) Run(ctx context.Context, inf Infrastructure) error {
	const path = "/etc/kubernetes/proxy/kubeconfig"

	ca, err := inf.Storage().GetCACertificate(ctx, "kubernetes")
	if err != nil {
		return err
	}
	crt, key, err := KubernetesCA{}.issueForProxy(ctx, inf)
	if err != nil {
		return err
	}
	cfg := proxyKubeconfig(c.cluster, ca, crt, key)
	src, err := clientcmd.Write(*cfg)
	if err != nil {
		return err
	}
	return makeFilesCommand{c.nodes, string(src), path}.Run(ctx, inf)
}

func (c makeProxyKubeconfigCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "make-proxy-kubeconfig",
		Target: strings.Join(targets, ","),
	}
}

type makeKubeletKubeconfigCommand struct {
	nodes   []*Node
	cluster string
	params  KubeletParams
}

func (c makeKubeletKubeconfigCommand) Run(ctx context.Context, inf Infrastructure) error {
	const kubeletConfigPath = "/etc/kubernetes/kubelet/config.yml"
	const kubeconfigPath = "/etc/kubernetes/kubelet/kubeconfig"
	caPath := K8sPKIPath("ca.crt")
	tlsCertPath := K8sPKIPath("kubelet.crt")
	tlsKeyPath := K8sPKIPath("kubelet.key")

	ca, err := inf.Storage().GetCACertificate(ctx, "kubernetes")
	if err != nil {
		return err
	}

	cfg := &KubeletConfiguration{
		APIVersion:            "kubelet.config.k8s.io/v1beta1",
		Kind:                  "KubeletConfiguration",
		ReadOnlyPort:          0,
		TLSCertFile:           tlsCertPath,
		TLSPrivateKeyFile:     tlsKeyPath,
		Authentication:        KubeletAuthentication{ClientCAFile: caPath},
		Authorization:         KubeletAuthorization{Mode: "Webhook"},
		HealthzBindAddress:    "0.0.0.0",
		ClusterDomain:         c.params.Domain,
		RuntimeRequestTimeout: "15m",
		FailSwapOn:            !c.params.AllowSwap,
	}
	cfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		n := n

		env.Go(func(ctx context.Context) error {
			err := writeFile(inf, n, caPath, ca)
			if err != nil {
				return err
			}

			crt, key, err := KubernetesCA{}.issueForKubelet(ctx, inf, n)
			if err != nil {
				return err
			}
			cfg := kubeletKubeconfig(c.cluster, n, ca, crt, key)
			kubeconfig, err := clientcmd.Write(*cfg)
			if err != nil {
				return err
			}
			err = writeFile(inf, n, kubeconfigPath, string(kubeconfig))
			if err != nil {
				return err
			}

			err = writeFile(inf, n, tlsCertPath, crt)
			if err != nil {
				return err
			}
			err = writeFile(inf, n, tlsKeyPath, key)
			if err != nil {
				return err
			}
			return writeFile(inf, n, kubeletConfigPath, string(cfgData))
		})
	}
	env.Stop()
	return env.Wait()
}

func (c makeKubeletKubeconfigCommand) Command() Command {
	targets := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		targets[i] = n.Address
	}
	return Command{
		Name:   "make-kubelet-kubeconfig",
		Target: strings.Join(targets, ","),
	}
}

type makeRBACRoleCommand struct {
	apiserver *Node
}

func (c makeRBACRoleCommand) Run(ctx context.Context, inf Infrastructure) error {
	cs, err := inf.K8sClient(c.apiserver)
	if err != nil {
		return err
	}

	_, err = cs.RbacV1().ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{
			Name: rbacRoleName,
			Labels: map[string]string{
				"kubernetes.io/bootstrapping": "rbac-defaults",
			},
			Annotations: map[string]string{
				// turn on auto-reconciliation
				// https://kubernetes.io/docs/reference/access-authn-authz/rbac/#auto-reconciliation
				"rbac.authorization.kubernetes.io/autoupdate": "true",
			},
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{""},
				// these are virtual resources.
				// see https://github.com/kubernetes/kubernetes/issues/44330#issuecomment-293768369
				Resources: []string{
					"nodes/proxy",
					"nodes/stats",
					"nodes/log",
					"nodes/spec",
					"nodes/metrics",
				},
				Verbs: []string{"*"},
			},
		},
	})

	return err
}

func (c makeRBACRoleCommand) Command() Command {
	return Command{
		Name:   "makeClusterRole",
		Target: rbacRoleName,
	}
}

type makeRBACRoleBindingCommand struct {
	apiserver *Node
}

func (c makeRBACRoleBindingCommand) Run(ctx context.Context, inf Infrastructure) error {
	cs, err := inf.K8sClient(c.apiserver)
	if err != nil {
		return err
	}

	_, err = cs.RbacV1().ClusterRoleBindings().Create(&rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: rbacRoleBindingName,
			Labels: map[string]string{
				"kubernetes.io/bootstrapping": "rbac-defaults",
			},
			Annotations: map[string]string{
				// turn on auto-reconciliation
				// https://kubernetes.io/docs/reference/access-authn-authz/rbac/#auto-reconciliation
				"rbac.authorization.kubernetes.io/autoupdate": "true",
			},
		},
		RoleRef: rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     rbacRoleName,
		},
		Subjects: []rbac.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "User",
				Name:     "kubernetes",
			},
		},
	})

	return err
}

func (c makeRBACRoleBindingCommand) Command() Command {
	return Command{
		Name:   "makeClusterRoleBinding",
		Target: rbacRoleBindingName,
	}
}

type killContainersCommand struct {
	nodes []*Node
	name  string
}

func (c killContainersCommand) Run(ctx context.Context, inf Infrastructure) error {
	env := cmd.NewEnvironment(ctx)
	for _, n := range c.nodes {
		ce := Docker(inf.Agent(n.Address))
		env.Go(func(ctx context.Context) error {
			exists, err := ce.Exists(c.name)
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			err = ce.Kill(c.name)
			if err != nil {
				return err
			}
			return ce.Remove(c.name)
		})
	}
	env.Stop()
	return env.Wait()
}

func (c killContainersCommand) Command() Command {
	addrs := make([]string, len(c.nodes))
	for i, n := range c.nodes {
		addrs[i] = n.Address
	}
	return Command{
		Name:   "kill-containers",
		Target: strings.Join(addrs, ","),
		Detail: c.name,
	}
}
