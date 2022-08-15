mod docker;
mod monitor;

use ctrlc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::runtime::Runtime;
use std::env;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Name of docker image to run
    #[clap(short, long, value_parser)]
    name: String,

    /// Optional master server to report local stats
    #[clap(short, long, value_parser)]
    server: Option<String>,

    /// Displaying debugging information
    #[clap(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

fn main() {
    // println!("Hello, world!");
    let cli = Cli::parse();

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

    match runtime.block_on(docker::create_and_run_container(&cli.name)) {
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

    if let Some(server) = cli.server.as_deref() {
        match monitor::report_result(server) {
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            },
            _ => {}
        }
    }
}

