module github.com/jetstack/cert-manager-webhook-servercow

go 1.13

require (
	github.com/go-acme/lego/v4 v4.1.3
	github.com/jetstack/cert-manager v0.13.1
	k8s.io/apiextensions-apiserver v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v0.17.0
	k8s.io/klog v1.0.0
)
