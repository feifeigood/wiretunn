use std::{path::PathBuf, str::FromStr};

use clap::{command, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};

use wiretunn::{bootstrap, config, log};

/// The app name
const NAME: &str = "Wiretunn";

/// Wiretunn is WireGuard implementation in Rust for Mesh Networking
///
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
}

impl Cli {
    pub fn run(self) {
        let _g = self.log_level().map(log::default);
        match self.command {
            Commands::Run { conf, .. } => run_service(conf),
            Commands::Test { conf } => match config::Config::load(conf) {
                Ok(_) => println!("Test configuration file is ok."),
                Err(err) => eprintln!("Test configuration file fail: {}", err),
            },
        }
    }

    pub fn log_level(&self) -> Option<tracing::Level> {
        self.verbose
            .log_level()
            .map(|s| s.to_string())
            .and_then(|s| tracing::Level::from_str(&s).ok())
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the WireTunn service
    Run {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,
        /// Pid file
        #[arg(short = 'p', long)]
        pid: Option<std::path::PathBuf>,
    },

    /// Test configuration and exit
    Test {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,
    },
}

fn main() {
    Cli::parse().run();
}

fn run_service(conf: Option<PathBuf>) {
    bootstrap(conf).expect("Failed to run Wiretunn");
    tracing::info!("{} {} shutdown", crate::NAME, wiretunn::version());
}
