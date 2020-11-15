import sys
# importing the bcc library from another folder
sys.path.insert(1, '/usr/lib/python3/dist-packages')

from bcc import BPF  # ignore this error, the line above imports BPF

bpf = None  # bpf is being used in more than 1 function, so it's global
start = 0  # this will be used to calculate the time elapsed between events


def print_event(cpu, data, size):
    global bpf
    global start
    event = bpf["events"].event(data)  # receive data_t's data from the bpf program
    # format output
    if start == 0:
        start = event.ts
    time_detected = (float(event.ts - start)) / 1000000000
    # time elapsed since the program first detected more than one "sync" calls in less than a second
    time_elapsed = float(event.delta) / 1000000
    # time elapsed since the last "sync" call
    print("Multiple sync calls detected at %.2f seconds" % time_detected, end=" - ")
    print("Time elapsed between calls: %.f milliseconds" % time_elapsed)


def main():
    # This BPF program will check if the system function "sync" is being called more than once
    # in less than a second. If it does, the program will also print the elapsed time between each call
    global bpf
    prog = """
    #include <linux/sched.h> // included in order to use "TASK_COMM_LEN"
    
    // define output data structure in C
    typedef struct data_t
    {
        u32 pid; // process id
        u64 ts; // process calling time
        u64 delta;
        char comm[TASK_COMM_LEN]; // process name
    } data_t;
    
    BPF_PERF_OUTPUT(events);
    BPF_HASH(last);
    
    int sync_timing(struct pt_regs *ctx)
    {
        data_t data = {};
        u64 *storedTime;
        u64 key = 0;
        
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        // attempt to read stored time
        storedTime = last.lookup(&key);
        if (storedTime != NULL)
        {
            data.ts = bpf_ktime_get_ns();
            data.delta = data.ts - *storedTime;
            if (data.delta < 1000000000)
            {
                // if time is less than 1 second
                events.perf_submit(ctx, &data, sizeof(data));
            }
            last.delete(&key);
        }

        // update stored timestamp
        data.ts = bpf_ktime_get_ns();
        last.update(&key, &data.ts);
        return 0;
    }
    """

    # load BPF program
    bpf = BPF(text=prog)
    bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"), fn_name="sync_timing")

    # header
    print("Tracing quick sync calls...")
    print("Press Ctrl+C to end")

    # loop with callback to print_event
    bpf["events"].open_perf_buffer(print_event)
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nTracing stopped")
            break


if __name__ == "__main__":
    main()
