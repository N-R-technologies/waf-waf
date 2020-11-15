import sys
# importing the bcc library from another folder
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the line above imports BPF

REQ_WRITE = 1  # from include/linux/blk_types.h


def main():
    # This BPF program will time disk I/O, and will print a histogram of their latency
    prog = """
    #include <uapi/linux/ptrace.h>
    #include <linux/blkdev.h>
    
    BPF_HASH(start, struct request *);
    BPF_HISTOGRAM(dist);
    
    int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
    {
        dist.increment(bpf_log2l(req->__data_len / 1024));
        return 0;
    }
    
    void trace_start(struct pt_regs *ctx, struct request *req)
    {
        // stash start timestamp by request ptr
        u64 ts = bpf_ktime_get_ns();
        start.update(&req, &ts);
    }
    
    void trace_completion(struct pt_regs *ctx, struct request *req)
    {
        u64 *storedTime;
        u64 delta;

        // attempt to read stored time
        storedTime = start.lookup(&req);
        if (storedTime != NULL)
        {
            delta = bpf_ktime_get_ns() - *storedTime;
            bpf_trace_printk("%d %x %d\\n", req->__data_len, req->cmd_flags, delta / 1000);
            start.delete(&req);
        }
    }
    """

    # load BPF program
    bpf = BPF(text=prog)
    if BPF.get_kprobe_functions(b'blk_start_request'):
        # called for every request (i think)
        bpf.attach_kprobe(event="blk_start_request", fn_name="trace_start")
    # called for every request (i think)
    bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
    # called for every finished I/O operation (i think)
    bpf.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")

    # header
    print("Timing disk I/O...")
    print("Press Ctrl+C to end")
    print("%-18s %-5s %-7s %8s" % ("TIME(s)", "TYPE", "BYTES", "LAT(ms)"))

    # format output
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
            (bytes_s, bflags_s, us_s) = msg.split()

            if int(bflags_s, 16) & REQ_WRITE:
                type_s = "W"  # write operation
            elif bytes_s == "0":  # see "blk_fill_rwbs()" for logic
                type_s = "M"  # i don't know what is this type
            else:
                type_s = "R"  # read operation
            ms = float(int(us_s, 10)) / 1000  # time it took to complete the operation

            print("%-18.9f %-5s %-4s %8.2f" % (ts, type_s, bytes_s.decode(), ms))
        except KeyboardInterrupt:
            print("\nTiming stopped")
            print("Histogram:")
            bpf["dist"].print_log2_hist("kbytes")  # histogram of disk I/O
            break


if __name__ == "__main__":
    main()
