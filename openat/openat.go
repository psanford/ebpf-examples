//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf openat.bpf.c -- -I../headers

const mapKey uint32 = 0

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	probe, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.RawTracepointSysEnter,
	})
	if err != nil {
		log.Fatalf("Attach raw tracepoint err: %s", err)
	}
	defer probe.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	data := make([][]byte, 16)
	for i := 0; i < len(data); i++ {
		data[i] = make([]byte, 4096)
	}

LOOP:
	for range ticker.C {
		mi := objs.TmpStorageMap.Iterate()
		more := true
		for more {
			d2 := data
			var k uint32
			more = mi.Next(&k, &d2)
			if !more {
				break
			}
			for i, d := range d2 {
				if d[0] == 0 {
					continue
				}
				log.Printf("k:%d i:%d v:%s\n", k, i, string(d))
			}
		}
		// if err := objs.TmpStorageMap.Lookup(mapKey, &d2); err != nil {
		// 	log.Fatalf("reading map: %s", err)
		// }
		// log.Printf("data %+v\n", d2)

		select {
		case <-sig:
			break LOOP
		default:
		}
	}
}
