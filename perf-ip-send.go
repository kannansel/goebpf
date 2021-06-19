/*
 * perf invoke perf on ip send
 *
 * Copyright : 2021
 */

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)


import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <net/inet_sock.h>

typedef struct {
	u32 pid;
	u32 ip;
	u32 dip;
	int code;
	int type;
	int ret;
} ip_event_t;

BPF_PERF_OUTPUT(ip_events);
BPF_HASH(ipcall, u64, ip_event_t);

int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb){
	u64 pid = bpf_get_current_pid_tgid();
	u32 sip;
	u32 dip;

	bpf_probe_read_kernel (&sip, sizeof(sip), skb->head+skb->network_header+12);
	bpf_probe_read_kernel (&dip, sizeof(dip), skb->head+skb->network_header+16);
	ip_event_t event = {
		.ip = sip,
		.dip= dip,
		.code=0,
		.type=0,
		.pid =pid >> 32,
	};
	ipcall.update (&pid, &event);
	return 0;
}

int kretprobe__ip_send_skb (struct pt_regs *ctx) {

	int ret = PT_REGS_RC (ctx);
	u64 pid = bpf_get_current_pid_tgid();
	ip_event_t *eventp = ipcall.lookup(&pid);
	if (eventp == 0) {
		return 0;
	}

	ip_event_t event = *eventp;
	event.ret = ret;
	ip_events.perf_submit (ctx, &event, sizeof(event));
	ipcall.delete (&pid);
	return 0;
}
`

type ipEvent struct {
	Pid	uint32
	Ip	uint32
	Dip	uint32
	Code	int32
	Type	int32
	Rval	int32
}


func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	ipKProbe, err := m.LoadKprobe("kprobe__ip_send_skb")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kprobe__ip_send_skb %s\n",err)
		os.Exit(1)
	}

	//syscallName := bpf.GetSyscallFnName("ip_send")

	err = m.AttachKprobe("ip_send_skb", ipKProbe, -1);

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe__ip_send_skb %s\n", err)
		os.Exit(1)
	}

	ipKretprobe, err := m.LoadKprobe("kretprobe__ip_send_skb")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kretprobe__ip_send_skb: %s\n",err)
		os.Exit(1)
	}

	err = m.AttachKretprobe("ip_send_skb", ipKretprobe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to Attach kretprobe__ip_send_skb: %s\n",err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("ip_events"),m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr,"Failed to init perf map:%s\n",err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {

		var event ipEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.BigEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data:%s \n",err)
				continue
			}

			fmt.Printf ("sip %08x dip %08x code %d type %d pid %d return val %d \n",
				    (event.Ip), event.Dip, event.Code, event.Type, event.Pid, event.Rval)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
