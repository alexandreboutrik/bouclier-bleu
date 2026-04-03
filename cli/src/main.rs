use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bouclier", about = "Bouclier Bleu Control Plane", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the status of the EDR
    Status,
    /// Enable a specific defense module
    Enable { module: String },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Status => {
            println!("🛡️ Bouclier Bleu EDR Status: KERNEL ENGINE RUNNING");
        }
        Commands::Enable { module } => {
            println!("· Enabling module: {}", module);
            println!("(Future: This will send a Unix Socket message to the `core` daemon)");
        }
    }
}
