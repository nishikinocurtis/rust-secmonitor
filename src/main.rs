use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
//use bcc::ring_buf::{RingBufBuilder, RingCallback};
use bcc::perf_event::{PerfMapBuilder};
use bcc::RawTracepoint;
use bcc::BccError;
use bcc::BPF;
use clap::{App, Arg};
use ctrlc;

#[repr(C)]
struct DataT {
    cgroup_id: u64,
    syscall_id: u32,
    pid: u32,
    comm: [u8; 16],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("secmonitor-rust")
        .about("Rust version of secmonitor")
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .value_name("Seconds")
                .help("The total duration to run")
                .takes_value(true),
        )
        .get_matches();

    let duration: Option<std::time::Duration> = matches
        .value_of("duration")
        .map(|v| std::time::Duration::new(v.parse().expect("Invalid argument for duration"), 0));

    let code = include_str!("bpf_raw_tp.c").to_string();
    let mut bpf = BPF::new(&code)?;

    RawTracepoint::new()
        .handler("do_trace")
        .tracepoint("sys_enter")
        .attach(&mut bpf)?;

    // let cb = ;

    let table = bpf.table("events")?;
    let mut perf_buf = PerfMapBuilder::new(table, perf_callback).build()?;

    println!(
        "{:-16} {:10} {:10}",
        "COMM", "PID", "SYSCALL_ID"
    );

    let start = Instant::now();
    while runnable.load(Ordering::SeqCst) {
        // println!("polling");
        perf_buf.poll(100);
        if let Some(d) = duration {
            if Instant::now() - start >= d {
                break;
            }
        }
    }
    Ok(())
}

fn parse_event_data(x: &[u8]) -> DataT {
    unsafe { std::ptr::read_unaligned(x.as_ptr() as *const DataT) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&c| c == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(&x[..]).to_string(),
    }
}

fn perf_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data = parse_event_data(&x);
        println!(
            "{:-16} {:10} {:10}",
            get_string(&data.comm),
            data.pid,
            data.syscall_id
        );
    })
}

fn main() {
    println!("Hello, world!");

    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    match do_main(runnable) {
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        _ => {}
    }
}
