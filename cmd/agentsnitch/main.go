package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/inspect"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "inspect":
		runInspect(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentsnitchctl inspect status|env|run|enable|disable|create-ca|remove-ca|trust-system|untrust-system|rotate-ca|purge-data [--expired]")
}

func runInspect(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		printJSON(currentInspectStatus())
	case "env":
		printInspectEnv()
	case "run":
		runWithInspectEnv(args[1:])
	case "enable":
		settings, err := inspect.LoadSettings()
		exitIf(err)
		settings.HTTPSInspectEnabled = true
		settings.HTTPSInspectProcessScoped = true
		settings.HTTPSInspectCapturePreviews = true
		settings.HTTPSInspectCaptureFull = false
		exitIf(inspect.SaveSettings(settings))
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, err := manager.EnsureCA()
		exitIf(err)
		fmt.Printf("HTTPS Inspect Mode enabled.\nCA fingerprint: %s\nTrust mode: process-scoped only\n", info.Fingerprint)
	case "disable":
		disableInspect(args[1:])
	case "create-ca":
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, err := manager.EnsureCA()
		exitIf(err)
		printJSON(info)
	case "remove-ca":
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, _ := manager.Info()
		if info.Present {
			cert, _ := loadCurrentCert()
			if inspect.SystemTrustStatus(cert).SystemTrusted {
				fmt.Printf("Removing AgentSnitch CA from macOS System trust.\nFingerprint: %s\nmacOS will request administrator approval.\n", info.Fingerprint)
				exitIf(inspect.RemoveSystemTrust(info.CAPath, cert))
			}
		}
		settings, err := inspect.LoadSettings()
		exitIf(err)
		settings.HTTPSInspectEnabled = false
		settings.HTTPSInspectProcessScoped = false
		settings.HTTPSInspectAllowSystemTrust = false
		settings.HTTPSInspectCapturePreviews = false
		settings.HTTPSInspectCaptureFull = false
		exitIf(inspect.SaveSettings(settings))
		exitIf(manager.DeleteCA())
		fmt.Println("AgentSnitch local CA material removed.")
	case "trust-system":
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, err := manager.EnsureCA()
		exitIf(err)
		fmt.Printf("Installing AgentSnitch CA in macOS System trust.\nFingerprint: %s\nmacOS will request administrator approval.\n", info.Fingerprint)
		exitIf(inspect.InstallSystemTrust(info.CAPath))
		settings, _ := inspect.LoadSettings()
		settings.HTTPSInspectAllowSystemTrust = true
		exitIf(inspect.SaveSettings(settings))
	case "untrust-system":
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, err := manager.Info()
		exitIf(err)
		cert, err := loadCurrentCert()
		exitIf(err)
		fmt.Printf("Removing AgentSnitch CA from macOS System trust.\nFingerprint: %s\nmacOS will request administrator approval.\n", info.Fingerprint)
		exitIf(inspect.RemoveSystemTrust(info.CAPath, cert))
		settings, _ := inspect.LoadSettings()
		settings.HTTPSInspectAllowSystemTrust = false
		exitIf(inspect.SaveSettings(settings))
	case "rotate-ca":
		manager := inspect.NewCertManager(inspect.DefaultPaths())
		info, err := manager.RotateCA()
		exitIf(err)
		printJSON(info)
	case "purge-data":
		purgeInspectData(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func purgeInspectData(args []string) {
	fs := flag.NewFlagSet("purge-data", flag.ExitOnError)
	expiredOnly := fs.Bool("expired", false, "delete only expired captured payload data")
	_ = fs.Parse(args)
	if *expiredOnly {
		exitIf(inspect.PurgeExpiredPayloads(inspect.DefaultPaths(), time.Now().UTC()))
		fmt.Println("Expired HTTPS Inspect payload data purged.")
		return
	}
	exitIf(inspect.PurgeData(inspect.DefaultPaths()))
	fmt.Println("Captured HTTPS Inspect payload data purged.")
}

func currentInspectStatus() inspect.Status {
	if runtimeStatus, err := asruntime.ReadStatus(); err == nil {
		status := inspect.CurrentStatus(runtimeStatus.Inspect.Proxy)
		status.ProcessEnv = runtimeStatus.Inspect.ProcessEnv
		if runtimeStatus.LastInspectedHTTP != nil {
			host := runtimeStatus.LastInspectedHTTP.Request.Host
			if host == "" {
				host = runtimeStatus.LastInspectedHTTP.Network.Remote
			}
			status.LastInspection = strings.TrimSpace(host)
		}
		return status
	}
	return inspect.CurrentStatus(inspect.ProxyStatus{})
}

func liveInspectEnv() map[string]string {
	status, err := asruntime.ReadStatus()
	exitIf(err)
	env := status.Inspect.ProcessEnv
	if len(env) == 0 {
		fmt.Fprintln(os.Stderr, "No live HTTPS Inspect process-scoped environment is available. Start or restart the AgentSnitch daemon with Inspect Mode enabled.")
		os.Exit(1)
	}
	return env
}

func printInspectEnv() {
	env := liveInspectEnv()
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("export %s=%s\n", key, shellExportValue(env[key]))
	}
}

func runWithInspectEnv(args []string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentsnitchctl inspect run -- <command> [args...]")
		os.Exit(2)
	}
	env := os.Environ()
	for key, value := range liveInspectEnv() {
		env = append(env, key+"="+value)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		exitIf(err)
	}
}

func shellExportValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func disableInspect(args []string) {
	fs := flag.NewFlagSet("disable", flag.ExitOnError)
	removeProcess := fs.Bool("remove-process-trust", true, "remove process-scoped trust bundle")
	purge := fs.Bool("purge-data", true, "delete captured payload data")
	deleteCA := fs.Bool("delete-ca", false, "delete local CA material")
	_ = fs.Parse(args)
	settings, err := inspect.LoadSettings()
	exitIf(err)
	settings.HTTPSInspectEnabled = false
	settings.HTTPSInspectCaptureFull = false
	exitIf(inspect.SaveSettings(settings))
	paths := inspect.DefaultPaths()
	if *removeProcess {
		_ = os.Remove(paths.BundlePath)
	}
	if *purge {
		exitIf(inspect.PurgeData(paths))
	}
	if *deleteCA {
		manager := inspect.NewCertManager(paths)
		cert, _ := loadCurrentCert()
		if inspect.SystemTrustStatus(cert).SystemTrusted {
			fmt.Fprintln(os.Stderr, "System trust is still installed. Run `agentsnitchctl inspect untrust-system` before deleting the CA.")
			os.Exit(1)
		}
		exitIf(manager.DeleteCA())
	}
	fmt.Println("HTTPS Inspect Mode disabled.")
}

func loadCurrentCert() (*x509Certificate, error) {
	cert, err := inspectCertificateForCLI(inspect.DefaultPaths().CAPath)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

type x509Certificate = x509.Certificate

func inspectCertificateForCLI(path string) (*x509Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("certificate PEM is invalid at %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	exitIf(enc.Encode(v))
}

func exitIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
	os.Exit(1)
}
