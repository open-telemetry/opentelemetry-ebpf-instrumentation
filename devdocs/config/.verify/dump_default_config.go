package main

import (
"fmt"
"os"

"gopkg.in/yaml.v3"

"go.opentelemetry.io/obi/pkg/obi"
)

func main() {
	b, err := yaml.Marshal(obi.DefaultConfig)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("devdocs/config/.verify/default-config-current.yaml", b, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote devdocs/config/.verify/default-config-current.yaml")
}
