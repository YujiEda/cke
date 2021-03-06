package clusterdns

import (
	"context"

	"github.com/cybozu-go/cke"
	"k8s.io/api/core/v1"
)

type updateConfigMapOp struct {
	apiserver *cke.Node
	configmap *v1.ConfigMap
	finished  bool
}

// UpdateConfigMapOp returns an Operator to update ConfigMap for CoreDNS.
func UpdateConfigMapOp(apiserver *cke.Node, configmap *v1.ConfigMap) cke.Operator {
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
	configmap *v1.ConfigMap
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
