package k8sclient

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// hold together the cluster node name and its IP address.
type NameAddressPair struct {
	Name    string
	Address string
}

// Get the ExternalIP entry of every node in the currently connected cluster.
func GetIPAddressList(clientset *kubernetes.Clientset) ([]*NameAddressPair, error) {
	var results []*NameAddressPair
	nodeList, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Couldn't get node list: %w", err)
	}

	for _, node := range nodeList.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeExternalIP {
				var temp NameAddressPair
				temp.Address = addr.Address
				temp.Name = node.Name
				results = append(results, &temp)
			}
		}
	}

	return results, nil
}

// Create a kubernetes client object to connect to the cluster. Support both
// out of cluster and in-cluster means of connecting.
func GetKubeClient() (*kubernetes.Clientset, error) {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "Absolute path to kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// first assume that we're connecting from outside the cluster
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {

		// we're probably inside the cluster, try to initiate from that
		config, err = rest.InClusterConfig()
		if err != nil {
			// nope, time to bail
			return nil, fmt.Errorf("Unable to initialize k8s client: %w", err)
		}

	}

	clientset, err := kubernetes.NewForConfig(config)

	return clientset, nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
