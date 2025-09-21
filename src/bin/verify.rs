use std::env;
use std::process;
use cover::policy::PolicyVerifier;
use cover::claims::ClaimsProcessor;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    match args[1].as_str() {
        "verify" => {
            if let Err(e) = handle_verify(&args) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
        "help" => {
            print_help(&args[0]);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage(&args[0]);
            process::exit(1);
        }
    }
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <command> [options]", program_name);
    eprintln!("Commands:");
    eprintln!("  verify <policy.rego> <input.json> [expected.json] - Verify policy against input");
    eprintln!("  help                                               - Show this help message");
}

fn print_help(program_name: &str) {
    println!("Cover CLI - Policy verification tool");
    println!();
    println!("Usage: {} <command> [options]", program_name);
    println!();
    println!("Commands:");
    println!("  verify <policy.rego> <input.json> [expected.json]");
    println!("    Verify a Rego policy against input data");
    println!("    - policy.rego:  Path to the Rego policy file");
    println!("    - input.json:   Path to the JSON input data file");
    println!("    - expected.json: (Optional) Path to expected appraisal result for validation");
    println!();
    println!("  help");
    println!("    Show this help message");
    println!();
    println!("Examples:");
    println!("  {} verify test/policy/cca-realm/policy.rego test/policy/cca-realm/input.json", program_name);
    println!("  {} verify test/policy/cca-realm/policy.rego test/policy/cca-realm/input.json test/policy/cca-realm/appraisal.json", program_name);
}

fn handle_verify(args: &[String]) -> Result<(), String> {
    if args.len() < 4 {
        return Err("verify command requires policy and input files. Use 'help' for usage.".to_string());
    }
    
    let policy_file = &args[2];
    let input_file = &args[3];
    let expected_file = args.get(4);
    
    println!("🔍 Starting policy verification...");
    println!("   Policy: {}", policy_file);
    println!("   Input:  {}", input_file);
    if let Some(expected) = expected_file {
        println!("   Expected: {}", expected);
    }
    println!();
    
    // Load and verify policy
    let verifier = PolicyVerifier::from_file(policy_file)?;
    
    // Process input claims first
    let input_content = std::fs::read_to_string(input_file)
        .map_err(|e| format!("Failed to read input file: {}", e))?;
    
    println!("📋 Analyzing input claims...");
    match ClaimsProcessor::process_claims(&input_content) {
        Ok(claims) => {
            println!("   Found {} claims:", claims.len());
            for claim in &claims {
                println!("   - Claim {}: {} (elements: {}, authority: {}, environment: {})", 
                    claim.index, 
                    claim.claim_type, 
                    claim.element_count,
                    claim.has_authority,
                    claim.has_environment
                );
            }
        }
        Err(e) => {
            println!("   Warning: Could not parse claims: {}", e);
        }
    }
    println!();
    
    // Verify policy
    println!("⚖️  Verifying policy...");
    let result = if let Some(expected) = expected_file {
        verifier.verify_with_files(input_file, Some(expected))?
    } else {
        verifier.verify_with_files(input_file, None::<&str>)?
    };
    
    // Display results
    println!("✅ Verification completed!");
    println!("   Status: {} ({})", result.status, if result.is_success() { "SUCCESS" } else { "WARNING/ERROR" });
    println!("   Message: {}", result.message);
    println!("   Policy: {}", result.policy_path);
    println!();
    println!("🛡️  Trustworthiness Vector:");
    println!("   Instance Identity: {}", result.trustworthiness_vector.instance_identity);
    println!("   Configuration:     {}", result.trustworthiness_vector.configuration);
    println!("   Executables:       {}", result.trustworthiness_vector.executables);
    println!("   File System:       {}", result.trustworthiness_vector.file_system);
    println!("   Hardware:          {}", result.trustworthiness_vector.hardware);
    println!("   Runtime Opaque:    {}", result.trustworthiness_vector.runtime_opaque);
    println!("   Storage Opaque:    {}", result.trustworthiness_vector.storage_opaque);
    println!("   Sourced Data:      {}", result.trustworthiness_vector.sourced_data);
    
    if result.is_success() {
        println!("\n🎉 Policy verification PASSED!");
    } else {
        println!("\n⚠️  Policy verification completed with warnings.");
    }
    
    Ok(())
}
