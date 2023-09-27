package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go nat ebpf/nat.c -- -Iebpf/headers
func main() {

}