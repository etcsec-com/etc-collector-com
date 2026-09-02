// ETC Collector - Active Directory & Azure Entra ID Security Auditing Tool
// Copyright 2025-2026 ETCSec
// Licensed under the Functional Source License, Version 1.1, ALv2 Future
// License (FSL-1.1-ALv2) — see LICENSE. Each version converts to
// Apache License 2.0 two years after its release.

package main

import (
	"os"
)

// Version is set at build time
var Version = "3.2.0"

// Edition — il n y a plus qu une seule edition depuis la v3.2.0 : le binaire
// embarque toutes les detections, ADCS et chemins d attaque compris. La valeur
// reste "pro" parce que c est celle que le cloud accepte deja pour un binaire
// qui contient ces detecteurs, et que son format de fil ne nous appartient pas.
// Retirer complètement ce champ est un changement de contrat a arbitrer avec
// l equipe cloud, pas une decision de build.
var Edition = "pro"

func main() {
	if err := Execute(); err != nil {
		os.Exit(1)
	}
}
