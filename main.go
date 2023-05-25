package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

func main() {
	tcIface := "enp0s3"
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	tcgo, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}

	// get all the qdiscs from all interfaces
	qdiscs, err := tcgo.Qdisc().Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get qdiscs: %v\n", err)
		return
	}
	clsactFound := false
	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get interface from id %d: %v", qdisc.Ifindex, err)
			return
		}
		if iface.Name == tcIface && qdisc.Kind == "clsact" {
			clsactFound = true
		}
	}

	if !clsactFound {
		qdisc := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(devID.Index),
				Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
				Parent:  tc.HandleIngress,
				Info:    0,
			},
			Attribute: tc.Attribute{
				Kind: "clsact",
			},
		}

		if err := tcgo.Qdisc().Add(&qdisc); err != nil {
			fmt.Printf("could not assign clsact to %s: %v, its already exists", tcIface, err)
		}
	}

	kernFile := "tc_program_kern.o"

	prg, err := ebpf.LoadCollection(kernFile)
	if err != nil {
		fmt.Println("LoadCollection error : ", err)
		return
	}
	defer prg.Close()

	bpfProg := prg.Programs["tc_program"]
	fd := uint32(bpfProg.FD())
	flags := uint32(0x1)

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}
	if err := tcgo.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return
	}

	tcfilts, err := tcgo.Filter().Get(&tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(devID.Index),
		Handle:  0x0,
		Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get filters for eBPF program: %v\n", err)
		return
	}
	for i := range tcfilts {
		fmt.Println(tcfilts[i].Msg.Info)
	}

	filter1 := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    tcfilts[0].Msg.Info,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	if err := tcgo.Filter().Delete(&filter1); err != nil {
		fmt.Fprintf(os.Stderr, "could not del filter for eBPF program: %v\n", err)
		return
	}
}
