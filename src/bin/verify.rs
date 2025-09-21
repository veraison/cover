use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <command>", args[0]);
        eprintln!("Commands:");
        eprintln!("  verify - Verify policy");
        eprintln!("  help   - Show this help message");
        process::exit(1);
    }
    
    match args[1].as_str() {
        "verify" => {
            println!("Policy verification functionality will be implemented here.");
            // TODO: Implement policy verification logic
        }
        "help" => {
            println!("Cover CLI - Policy verification tool");
            println!("Usage: {} <command>", args[0]);
            println!("Commands:");
            println!("  verify - Verify policy");
            println!("  help   - Show this help message");
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use 'help' for available commands.");
            process::exit(1);
        }
    }
}
