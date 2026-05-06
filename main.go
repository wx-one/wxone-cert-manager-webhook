package main

import (
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

// IMPORTANT: This must match the groupName used in your Issuer/ClusterIssuer.
var GroupName = "acme.wx1.eu"

func main() {
	cmd.RunWebhookServer(GroupName, &wx1Solver{})
}
