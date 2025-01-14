use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::{self, Inferior};
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    breakpoints: Vec<usize>,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // TODO (milestone 3): initialize the DwarfData
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
            }
        };

        debug_data.print();

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            breakpoints: vec![],
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if self.inferior.is_some() {
                        let inferior = self.inferior.as_mut().unwrap();
                        inferior.kill_and_reap();
                    }

                    if let Some(inferior) = Inferior::new(&self.target, &args, &self.breakpoints) {
                        // Create the inferior
                        self.inferior = Some(inferior);
                        // TODO (milestone 1): make the inferior run
                        // You may use self.inferior.as_mut().unwrap() to get a mutable reference
                        // to the Inferior object
                        self.restart_child();
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::Cont => {
                    if self.inferior.is_none() {
                        println!("Error: no process has started yet");
                        continue;
                    }
                    self.restart_child();
                }
                DebuggerCommand::Back => {
                    let inferior = self.inferior.as_mut().unwrap();
                    inferior
                        .print_backtrace(&self.debug_data)
                        .expect("can not backtrace");
                }
                DebuggerCommand::Break(breakpoint) => {
                    let addr: usize;
                    if breakpoint.starts_with("*") {
                        addr = parse_address(&breakpoint[1..]).unwrap();
                    } else {
                        if let Some(val) = self.debug_data.get_addr_for_function(None, &breakpoint)
                        {
                            addr = val;
                        } else {
                            println!("there is no function named {} in the file", breakpoint);
                            continue;
                        }
                    }

                    self.install_breakpoint(addr);
                }
                DebuggerCommand::Quit => {
                    if self.inferior.is_some() {
                        let inferior = self.inferior.as_mut().unwrap();
                        inferior.kill_and_reap();
                    }
                    return;
                }
            }
        }
    }

    fn install_breakpoint(&mut self, addr: usize) {
        self.breakpoints.push(addr);
        if let Some(inferior) = self.inferior.as_mut() {
            inferior
                .install_breakpoint(addr)
                .expect("can not install breakpoint");
        }
        println!(
            "Set breakpoint {} at 0x{:x}",
            self.breakpoints.len() - 1,
            addr
        );
    }

    fn restart_child(&mut self) {
        let inferior = self.inferior.as_mut().unwrap();
        match inferior.cont() {
            Ok(status) => match status {
                inferior::Status::Exited(code) => {
                    println!("Child exited (status {})", code);
                    self.inferior = None;
                }

                inferior::Status::Stopped(sig, reg) => {
                    println!("Chid stopped (signal {})", sig);
                    if let Some(line) = self.debug_data.get_line_from_addr(reg) {
                        println!("Stopped at {}", line);
                    }
                }
                _ => {}
            },

            Err(err) => {
                panic!("Error in continuing subprocess: {}", err);
            }
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}

fn parse_address(addr: &str) -> Option<usize> {
    let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    usize::from_str_radix(addr_without_0x, 16).ok()
}

