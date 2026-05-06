package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	webhookapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type wx1Solver struct {
	kube kubernetes.Interface
}

func (s *wx1Solver) Name() string {
	return "wx1"
}

type secretRef struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	UsernameKey string `json:"usernameKey"`
	PasswordKey string `json:"passwordKey"`
}

type solverConfig struct {
	Host          string    `json:"host"`
	ProjectID     string    `json:"projectId"`
	ZoneID        string    `json:"zoneId"`
	AuthSecretRef secretRef `json:"authSecretRef"`
}

func (s *wx1Solver) Initialize(cfg *rest.Config, _ <-chan struct{}) error {
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	s.kube = c
	return nil
}

func (s *wx1Solver) Present(ch *webhookapi.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	username, password, err := s.readCreds(cfg.AuthSecretRef)
	if err != nil {
		return err
	}

	cli := newWxOneClient(cfg.Host, "wizardtales.com")
	if err := cli.Login(context.Background(), username, password); err != nil {
		return err
	}

	projectId, err := resolveProjectID(cli, cfg.ProjectID)
	if err != nil {
		return err
	}

	fqdn := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	if fqdn == "" {
		return fmt.Errorf("empty ResolvedFQDN")
	}

	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")

	zoneId := cfg.ZoneID
	if zoneId == "" {
		zones, err := cli.GetDomainZones(context.Background(), projectId)
		if err != nil {
			return err
		}
		var matched *domainZone
		for i, z := range zones {
			if z.Domain == domain || strings.HasSuffix(domain, "."+z.Domain) {
				matched = &zones[i]
				break
			}
		}
		if matched == nil {
			return fmt.Errorf("no matching zone found for domain %s", domain)
		}
		zoneId = matched.ID
	}

	return cli.EnsureTXT(
		context.Background(),
		projectId,
		zoneId,
		fqdn,
		60,
		ch.Key,
	)
}

func (s *wx1Solver) CleanUp(ch *webhookapi.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	username, password, err := s.readCreds(cfg.AuthSecretRef)
	if err != nil {
		return err
	}

	cli := newWxOneClient(cfg.Host, "wizardtales.com")
	if err := cli.Login(context.Background(), username, password); err != nil {
		return err
	}

	projectId, err := resolveProjectID(cli, cfg.ProjectID)
	if err != nil {
		return err
	}

	fqdn := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	if fqdn == "" {
		return nil
	}

	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")

	zoneId := cfg.ZoneID
	if zoneId == "" {
		zones, err := cli.GetDomainZones(context.Background(), projectId)
		if err != nil {
			return err
		}
		var matched *domainZone
		for i, z := range zones {
			if z.Domain == domain || strings.HasSuffix(domain, "."+z.Domain) {
				matched = &zones[i]
				break
			}
		}
		if matched == nil {
			return fmt.Errorf("no matching zone found for domain %s", domain)
		}
		zoneId = matched.ID
	}

	return cli.RemoveTXT(
		context.Background(),
		projectId,
		zoneId,
		fqdn,
		ch.Key,
	)
}

func loadConfig(cfgJSON *apiextensionsv1.JSON, fallbackNS string) (*solverConfig, error) {
	if cfgJSON == nil || len(cfgJSON.Raw) == 0 {
		return nil, fmt.Errorf("missing solver config")
	}

	var cfg solverConfig
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, err
	}

	if cfg.Host == "" {
		return nil, fmt.Errorf("host is required")
	}

	if cfg.AuthSecretRef.Name == "" {
		return nil, fmt.Errorf("authSecretRef.name is required")
	}
	if cfg.AuthSecretRef.Namespace == "" {
		cfg.AuthSecretRef.Namespace = fallbackNS
		if cfg.AuthSecretRef.Namespace == "" {
			cfg.AuthSecretRef.Namespace = "cert-manager"
		}
	}
	if cfg.AuthSecretRef.UsernameKey == "" {
		cfg.AuthSecretRef.UsernameKey = "username"
	}
	if cfg.AuthSecretRef.PasswordKey == "" {
		cfg.AuthSecretRef.PasswordKey = "password"
	}

	return &cfg, nil
}

func resolveProjectID(cli *wxOneClient, projectID string) (string, error) {
	if projectID != "" {
		return projectID, nil
	}

	proj, err := cli.GetDefaultProject(context.Background())
	if err != nil {
		return "", err
	}
	return proj.ID, nil
}

func (s *wx1Solver) readCreds(ref secretRef) (string, string, error) {
	sec, err := s.kube.CoreV1().Secrets(ref.Namespace).Get(
		context.Background(),
		ref.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		return "", "", err
	}

	u := strings.TrimSpace(string(sec.Data[ref.UsernameKey]))
	p := string(sec.Data[ref.PasswordKey])

	if u == "" || p == "" {
		return "", "", fmt.Errorf("missing username/password in secret")
	}
	return u, p, nil
}
