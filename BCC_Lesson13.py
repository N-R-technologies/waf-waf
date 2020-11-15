import sys
# importing the bcc library from another folder
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the line above imports BPF

REQ_WRITE = 1  # from include/linux/blk_types.h
bpf = None  # bpf is being used in more than 1 function, so it's global


def print_event(cpu, data, size):
    global bpf
    event = bpf["events"].event(data)  # receive data_t's data from the bpf program
    # format output
    if int(event.bflags_s, 16) & REQ_WRITE:
        type_s = "W"  # write operation
    elif event.bytes_s == "0":  # see "blk_fill_rwbs()" for logic
        type_s = "M"  # i don't know what is this type
    else:
        type_s = "R"  # read operation
    ms = float(int(event.delta, 10)) / 1000  # time it took to complete the operation in milliseconds

    print("%-18.9f %-5s %-4s %8.2f" % (event.ts, type_s, event.bytes_s, ms))


def main():
    # Im not sure what this BPF program will do, but it should do something similar to time disk I/O,
    # using "block_rq_issue" and "block_rq_complete".
    # I don't know if this program works, because it didn't do anything when i tried to run it,
    # but i think it should work
    prog = """
    #include <uapi/linux/ptrace.h>
    #include <linux/blkdev.h>
    
    // define output data structure in C
    typedef struct data_t
    {
        u32 bytes_s;
        u32 bflags_s;
        u64 ts;
        u64 delta;
    } data_t;
    
    BPF_PERF_OUTPUT(events);
    BPF_HASH(start, struct request *);

    int block_rq_issue(struct pt_regs *ctx, struct request *req)
    {
        // stash start timestamp by request ptr
        u64 ts = bpf_ktime_get_ns();
        start.update(&req, &ts);
        return 0;
    }

    int block_rq_complete(struct pt_regs *ctx, struct request *req)
    {
        data_t data = {};
        u64 *storedTime;
        
        // attempt to read stored time
        storedTime = start.lookup(&req);
        if (storedTime != NULL)
        {
            data.ts = bpf_ktime_get_ns();
            data.delta = (data.ts - *storedTime) / 1000;
            data.bytes_s = req->__data_len;
            data.bflags_s = req->cmd_flags;
            events.perf_submit(ctx, &data, sizeof(data));
            start.delete(&req);
        }
        return 0;
   }
    """

    # load BPF program
    bpf = BPF(text=prog)

    # header
    print("Timing disk I/O...")
    print("Press Ctrl+C to end")
    print("%-18s %-5s %-7s %8s" % ("TIME(s)", "TYPE", "BYTES", "LAT(ms)"))

    # loop with callback to print_event
    bpf["events"].open_perf_buffer(print_event)
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nTiming stopped")
            break


if __name__ == "__main__":
    main()
