package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/aegis-sigma/engine/pkg/bridgemain"
	"github.com/aegis-sigma/engine/pkg/bridgeswot"
	"github.com/aegis-sigma/engine/pkg/bridgetools"
)

func main() {
	mainPort := getEnvInt("BRIDGE_MAIN_PORT", 8899)
	swotPort := getEnvInt("BRIDGE_SWOT_PORT", 8900)
	toolsPort := getEnvInt("BRIDGE_TOOLS_PORT", 8901)

	var wg sync.WaitGroup

	wg.Add(3)
	go func() {
		defer wg.Done()
		srv := &http.Server{Addr: fmt.Sprintf(":%d", swotPort), Handler: bridgeswot.NewHandler()}
		fmt.Printf("[BRIDGE] SWOT on :%d\n", swotPort)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "[BRIDGE] SWOT error: %v\n", err)
		}
	}()

	go func() {
		defer wg.Done()
		srv := &http.Server{Addr: fmt.Sprintf(":%d", toolsPort), Handler: bridgetools.NewHandler()}
		fmt.Printf("[BRIDGE] Tools on :%d\n", toolsPort)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "[BRIDGE] Tools error: %v\n", err)
		}
	}()

	srv := &http.Server{Addr: fmt.Sprintf(":%d", mainPort), Handler: bridgemain.NewHandler()}
	fmt.Printf("[BRIDGE] Main on :%d\n", mainPort)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "[BRIDGE] Main error: %v\n", err)
	}
	wg.Wait()
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
