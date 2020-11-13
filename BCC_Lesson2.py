import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the program is able to run


def main():
    bpf_script = """
    int kprobe__sys_sync(void *ctx)
    {
        bpf_trace_printk("sys_sync() called\\n");
        return 0;
    }
    """

    bpf_object = BPF(text=bpf_script)
    try:
        print("Tracing sys_sync()...")
        print("Press Ctrl+C to end")
        bpf_object.trace_print()

    except KeyboardInterrupt:
        print("\nTracing stopped")


if __name__ == "__main__":
    main()
