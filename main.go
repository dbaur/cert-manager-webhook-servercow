package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v4/providers/dns/servercow"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&servercowDNSProviderSolver{},
	)
}

// servercowDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type servercowDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// servercowDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type servercowDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	Namespace       string                   `json:"namespace"`
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *servercowDNSProviderSolver) Name() string {
	return "servercow"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *servercowDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {

	fmt.Printf("Presented with new challenge %s", ch)

	sc, err := c.getServercowClient(ch)
	if err != nil {
		return err
	}

	//domain, _ := c.getZone(ch.ResolvedZone)

	err = sc.Present(ch.DNSName, ch.Key, "")
	if err != nil {
		return err
	}

	return nil
}

func (c *servercowDNSProviderSolver) getZone(fqdn string) (string, error) {
	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}

	return util.UnFqdn(authZone), nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *servercowDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console

	sc, err := c.getServercowClient(ch)
	if err != nil {
		return err
	}
	err = sc.CleanUp(ch.DNSName, ch.Key, "")
	if err != nil {
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *servercowDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	fmt.Print("Initializing the DNS Solver for Servercow")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

func (c *servercowDNSProviderSolver) getServercowClient(ch *v1alpha1.ChallengeRequest) (*servercow.DNSProvider, error) {

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	username, password, err := c.getUsernamePassword(&cfg, &cfg.Namespace)
	if err != nil {
		return nil, err
	}

	config := servercow.NewDefaultConfig()

	config.Password = *password
	config.Username = *username
	dnsProvider, err := servercow.NewDNSProviderConfig(config)
	if err != nil {
		return nil, err
	}

	return dnsProvider, nil

}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (servercowDNSProviderConfig, error) {
	cfg := servercowDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// Get Servercow Credentials from Kubernetes secret.
func (c *servercowDNSProviderSolver) getUsernamePassword(cfg *servercowDNSProviderConfig, namespace *string) (*string, *string, error) {
	secretName := cfg.APIKeySecretRef.LocalObjectReference.Name

	fmt.Printf("try to load secret %s with key %s", secretName, cfg.APIKeySecretRef.Key)

	sec, err := c.client.CoreV1().Secrets(*namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}

	usernameBytes, ok := sec.Data["username"]
	if !ok {
		return nil, nil, fmt.Errorf("key username not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key,
			cfg.APIKeySecretRef.LocalObjectReference.Name, namespace)
	}

	username := string(usernameBytes)

	passwordBytes, ok := sec.Data["password"]
	if !ok {
		return nil, nil, fmt.Errorf("key password not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key,
			cfg.APIKeySecretRef.LocalObjectReference.Name, namespace)
	}

	password := string(passwordBytes)

	return &username, &password, nil
}
