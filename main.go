// Package main is the entry point for the Cosmian KMS Terraform provider.
// Published to registry.terraform.io under cosmian/kms.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/cosmian/terraform-provider-kms/internal/provider"
)

// version is set at release time via -ldflags.
var version string = "dev"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "run provider with delve debugger support")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/cosmian/kms",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
