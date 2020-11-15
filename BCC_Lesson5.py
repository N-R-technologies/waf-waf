import sys
# importing the bcc library from another folder
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the line above imports BPF


def main():
    # This BPF program will print how many times the system function
    # "sync" has been called everytime time it is being called
    prog = """
    BPF_HASH(last);

    int trace_sync_count(struct pt_regs *ctx)
    {
        u64 *storedCounter;
        u64 counter = 1;
        u64 key = 0;

        // attempt to read stored counter
        storedCounter = last.lookup(&key);
        if (storedCounter != NULL)
        {
            counter = *storedCounter + 1;
            last.delete(&key);
        }
        bpf_trace_printk("%d\\n", counter);
    
        // update stored counter
        last.update(&key, &counter);
        return 0;
    }
    """

    # load BPF program
    bpf = BPF(text=prog)
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"), fn_name="trace_sync_count")

    # header
    print("Counting sync calls...")
    print("Press Ctrl+C to end")

    # format output
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
            print("Sync count:", msg.decode())  # the type of msg is bytes, so it's being decoded
        except KeyboardInterrupt:
            print("\nTracing stopped")
            break


if __name__ == "__main__":
    main()
