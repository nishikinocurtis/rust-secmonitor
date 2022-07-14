use std::sync::{Arc, Once, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::fs::File;
//use bcc::ring_buf::{RingBufBuilder, RingCallback};
use bcc::perf_event::{PerfMapBuilder};
use bcc::RawTracepoint;
use bcc::BccError;
use bcc::BPF;
use clap::{App, Arg};
use lazy_static::lazy_static;
use serde_json;


#[repr(C)]
struct DataT {
    cgroup_id: u64,
    syscall_id: u32,
    pid: u32,
    comm: [u8; 16],
}

static mut CGROUP_FLAG: u64 = 0;
static INIT_CGROUP_FLAG: Once = Once::new();
static mut PROC_LIST: Vec<u32> = Vec::<u32>::new();
static INIT_PROC_LIST: Once = Once::new();

pub(crate) fn load_prog() -> Result<BPF, BccError> {
    let code = include_str!("bpf_raw_tp.c").to_string();
    let mut bpf = BPF::new(&code)?;

    match RawTracepoint::new()
        .handler("do_trace")
        .tracepoint("sys_enter")
        .attach(&mut bpf) {
        Err(e) => {Err(e)},
        _ => {Ok(bpf)}
    }
}

pub(crate) fn do_main(runnable: Arc<AtomicBool>, bpf: BPF, proc_list: Vec::<u32>) -> Result<(), BccError> {
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
    // let cb = ;

    // let cgroup_flag = Arc::new(0u64);
    // let proc_list_ptr = Arc::new(proc_list);
    unsafe {
        INIT_PROC_LIST.call_once(|| {
            PROC_LIST = proc_list;
        });
    }


    let table = bpf.table("events")?;
    let mut perf_buf = PerfMapBuilder::new(table, perf_callback).build()?;


    // create an Arc to cgroup_flag, pass to callback and clone.

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

fn get_proc_list() -> Vec<u32> {
    unsafe {
        PROC_LIST.clone()
    }
}

fn set_cgroup_flag(cgroup_id: u64) {
    unsafe {
        INIT_CGROUP_FLAG.call_once(|| {
            CGROUP_FLAG = cgroup_id;
        });
    }
}
fn get_cgroup_flag() -> u64 {
    unsafe {
        CGROUP_FLAG
    }
}

lazy_static! {
    static ref SYSCALL_COUNTER: Mutex<HashMap<u32, u64>> = Mutex::new(HashMap::<u32, u64>::new());
}

fn push_syscall(syscall_id: u32) {
    let mut op_mutex = SYSCALL_COUNTER.lock().unwrap();
    match op_mutex.get_mut(&syscall_id) {
        Some(v) => { *v += 1; },
        None => { op_mutex.insert(syscall_id, 1); },
    }
}

pub(crate) fn dump_result() -> Result<(), std::io::Error>{
    let file = File::create("secmonitor-stats.json")?;
    serde_json::to_writer(file, &SYSCALL_COUNTER.lock().unwrap().clone())?;
    
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

        if get_cgroup_flag() == data.cgroup_id {
            println!(
                "{:-16} {:10} {:10}",
                get_string(&data.comm),
                data.pid,
                data.syscall_id
            );
            push_syscall(data.syscall_id);
        } else {
            let mut into_iter = get_proc_list().into_iter();
            match into_iter.find(|&x| x == data.pid) {
                Some(_) => {
                    set_cgroup_flag(data.cgroup_id);
                    println!(
                        "{:-16} {:10} {:10}",
                        get_string(&data.comm),
                        data.pid,
                        data.syscall_id
                    );
                    push_syscall(data.syscall_id);
                },
                None => {}
            }
        }
    })
}

