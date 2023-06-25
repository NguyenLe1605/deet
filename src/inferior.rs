use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;

use crate::dwarf_data::DwarfData;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
        // TODO: implement me!
        let mut c = Command::new(target);
        let cmd = c.args(args);
        unsafe {
            cmd.pre_exec(|| child_traceme());
        }

        if let Ok(child) = cmd.spawn() {
            let inferior = Inferior{
                child: child
            };

            return match inferior.wait(None) {
                Err(_) => None,
                Ok(status) => match status {
                    Status::Stopped(signal, _) => {
                        match signal {
                            signal::SIGTRAP => Some(inferior),
                            _ => None
                        }
                    }
                    _ => None
                }
            }       
        }

        None
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    // Wakes up the inferior and waits until it finished and terminates.
    pub fn cont(&self) -> Result<Status, nix::Error> {
        ptrace::cont(self.pid(), None)?;
        return self.wait(None);
    }

    // Kills a process and reaps it.
    pub fn kill_and_reap(&mut self) {
        match self.child.kill() {
            Ok(()) => {
                self.wait(None).expect("can not reap the process");
            },
            Err(err) => {
                panic!("Error: {}", err);
            }
        };
    }

    fn read_mem(&self, addr: usize) -> Result<usize, nix::Error> {
        let mem = ptrace::read(self.pid(), addr as ptrace::AddressType)? as usize;
        Ok(mem)
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error> {
        let reg = ptrace::getregs(self.pid())?;
        let mut inst_ptr = reg.rip as usize;
        let mut base_ptr = reg.rbp as usize;
        loop {
            let line = debug_data.get_line_from_addr(inst_ptr)
                .expect("can not read the line from rip");
            let func = debug_data.get_function_from_addr(inst_ptr)
                .expect("can not get function from rip");
            println!("{} ({})", func, line);

            if func == "main" {
                break;
            }

            inst_ptr = self.read_mem(base_ptr + 8)?;
            base_ptr = self.read_mem(base_ptr)?;
        }
        Ok(())
    }
}
