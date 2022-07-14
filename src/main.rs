mod docker;
mod monitor;

use ctrlc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::runtime::Runtime;

fn main() {
    println!("Hello, world!");

    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let bpf = match monitor::load_prog() {
        Ok(bpf) => {
            println!("Loaded BPF program");
            bpf
        },
        Err(e) => {
            println!("Error loading BPF program: {}", e);
            std::process::exit(1);
        }
    };

    let runtime = Runtime::new().unwrap();

    let mut proc_list = Vec::<u32>::new();

    match runtime.block_on(docker::create_and_run_container("nginx")) {
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        },
        Ok(response) => {
            println!("Container preparation done");
            match response.processes {
                Some(processes) => {
                    for proc in processes {
                        let pid = proc[1].parse::<u32>().unwrap();
                        proc_list.push(pid);
                    }
                },
                None => {
                    eprintln!("Error: no processes found");
                    std::process::exit(1);
                }
            }
        }
    }

    match monitor::do_main(runnable, bpf, proc_list) {
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        },
        _ => {}
    }
    
    match monitor::dump_result() {
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        },
        _ => {}
    }
}
