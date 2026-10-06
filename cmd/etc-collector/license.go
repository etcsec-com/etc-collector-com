package main

import (
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"
)

//go:embed license.txt
var licenseText string

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Display the software license",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(licenseText)
	},
}

func init() {
	rootCmd.AddCommand(licenseCmd)
}
