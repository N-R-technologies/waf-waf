import sys
# importing the bcc library from another folder
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the line above imports BPF


def main():
    # This BPF program will print "sys_sync() called"
    # everytime the system function "sync" is being called
    prog = """
    int kprobe__sys_sync(void *ctx)
    {
        bpf_trace_printk("sys_sync() called\\n");
        return 0;
    }
    """

    # load BPF program
    bpf = BPF(text=prog)
    try:
        # header
        print("Tracing sys_sync()...")
        print("Press Ctrl+C to end")
        # output
        bpf.trace_print()
    except KeyboardInterrupt:
        print("\nTracing stopped")


if __name__ == "__main__":
    main()
