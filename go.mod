module github.com/jetstack/cert-manager-webhook-servercow

go 1.13

require (
	github.com/go-acme/lego/v4 v4.1.3
	github.com/jetstack/cert-manager v1.1.0
	k8s.io/apiextensions-apiserver v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
)

replace github.com/go-acme/lego/v4 => github.com/dbaur/lego/v4 v4.1.3-dbaur
