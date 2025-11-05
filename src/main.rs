use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process;

mod capabilities;
mod kernel;
mod nic;
mod output;
mod runtime;
mod system;

#[derive(Parser)]
#[command(name = "xdp-check")]
#[command(about = "XDP compatibility checker - verify system XDP support and runtime status")]
#[command(version, long_about = None)]
struct Cli {
    #[arg(short = 'f', long, value_enum, default_value = "human")]
    format: OutputFormat,

    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// default
    Check {
        #[arg(long)]
        skip_runtime: bool,
    },
    Kernel,
    Nic {
        /// (e.g., eth0, ens3)
        interface: String,
    },
    /// verify if XDP is currently active on the system
    Runtime {
        interface: Option<String>,
    },
    Quick,
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match cli.command {
        None | Some(Commands::Check { .. }) => run_full_check(&cli),
        Some(Commands::Kernel) => run_kernel_check(&cli),
        Some(Commands::Nic { ref interface }) => run_nic_check(&cli, interface),
        Some(Commands::Runtime { ref interface }) => run_runtime_check(&cli, interface.as_deref()),
        Some(Commands::Quick) => run_quick_check(&cli),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        process::exit(1);
    }
}

fn run_full_check(cli: &Cli) -> Result<()> {
    let mut report = output::Report::new();

    println!("{}", "XDP Compatibility Check".cyan().bold());
    println!("{}", "========================".cyan());
    println!();

    println!("{}", "Checking kernel compatibility...".yellow());
    let kernel_results = kernel::check_kernel_compatibility()?;
    report.add_section("Kernel", kernel_results);

    println!("{}", "Checking capabilities...".yellow());
    let cap_results = capabilities::check_capabilities()?;
    report.add_section("Capabilities", cap_results);

    println!("{}", "Checking system resources...".yellow());
    let sys_results = system::check_system_resources()?;
    report.add_section("System Resources", sys_results);

    println!("{}", "Checking network interfaces...".yellow());
    let nic_results = nic::check_all_interfaces()?;
    report.add_section("Network Interfaces", nic_results);

    if !matches!(cli.command, Some(Commands::Check { skip_runtime: true, .. })) {
        println!("{}", "Checking XDP runtime status...".yellow());
        let runtime_results = runtime::check_xdp_runtime(None)?;
        report.add_section("Runtime Status", runtime_results);
    }

    println!();
    match cli.format {
        OutputFormat::Human => report.print_human(cli.verbose),
        OutputFormat::Json => report.print_json()?,
    }

    if !report.is_compatible() {
        process::exit(1);
    }

    Ok(())
}

fn run_kernel_check(cli: &Cli) -> Result<()> {
    let mut report = output::Report::new();

    println!("{}", "Kernel Compatibility Check".cyan().bold());
    println!("{}", "==========================".cyan());
    println!();

    let kernel_results = kernel::check_kernel_compatibility()?;
    report.add_section("Kernel", kernel_results);

    match cli.format {
        OutputFormat::Human => report.print_human(cli.verbose),
        OutputFormat::Json => report.print_json()?,
    }

    if !report.is_compatible() {
        process::exit(1);
    }

    Ok(())
}

fn run_nic_check(cli: &Cli, interface: &str) -> Result<()> {
    let mut report = output::Report::new();

    println!("{}", format!("NIC Compatibility Check: {}", interface).cyan().bold());
    println!("{}", "================================".cyan());
    println!();

    let nic_results = nic::check_interface(interface)?;
    report.add_section(&format!("Interface: {}", interface), nic_results);

    match cli.format {
        OutputFormat::Human => report.print_human(cli.verbose),
        OutputFormat::Json => report.print_json()?,
    }

    if !report.is_compatible() {
        process::exit(1);
    }

    Ok(())
}

fn run_runtime_check(cli: &Cli, interface: Option<&str>) -> Result<()> {
    let mut report = output::Report::new();

    println!("{}", "XDP Runtime Status Check".cyan().bold());
    println!("{}", "========================".cyan());
    println!();

    let runtime_results = runtime::check_xdp_runtime(interface)?;
    report.add_section("Runtime Status", runtime_results);

    match cli.format {
        OutputFormat::Human => report.print_human(cli.verbose),
        OutputFormat::Json => report.print_json()?,
    }

    Ok(())
}

fn run_quick_check(cli: &Cli) -> Result<()> {
    let mut report = output::Report::new();

    println!("{}", "Quick XDP Check".cyan().bold());
    println!("{}", "===============".cyan());
    println!();

    let kernel_results = kernel::quick_kernel_check()?;
    report.add_section("Kernel", kernel_results);

    let cap_results = capabilities::quick_capability_check()?;
    report.add_section("Capabilities", cap_results);

    let nic_results = nic::quick_interface_check()?;
    report.add_section("Network Interfaces", nic_results);

    match cli.format {
        OutputFormat::Human => report.print_human(cli.verbose),
        OutputFormat::Json => report.print_json()?,
    }

    if !report.is_compatible() {
        process::exit(1);
    }

    Ok(())
}