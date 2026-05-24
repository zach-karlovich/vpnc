mod cli;
mod dns;
mod net;
mod platform;
mod report;
mod vpn;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let report = report::StatusReport::build(&cli);
    report.print_compact(cli.verbose, cli.json);
}
