//! The command-line face of the client: sync, show, add.

use std::io::Write;

use icp_core::engine::Engine;
use icp_core::keychain::Credential;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = match command {
        "sync" => cmd_sync(&args),
        "show" => cmd_show(&args),
        "add" => cmd_add(&args),
        "check" => cmd_check(),
        "dump" => cmd_dump(),
        "update" => cmd_update(&args),
        "delete" => cmd_delete(&args),
        _ => {
            usage();
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    println!(
        "usage: icp <command>

  sync            fetch the keychain and decrypt it into the vault
  show [query]    list the credentials in the vault
  add <domain>    add a login to the iCloud Keychain
  check           report what the client can see (no secrets)
"
    );
}

fn open() -> Result<Engine, String> {
    Engine::open(None).map_err(|e| e.to_string())
}

fn cmd_sync(_args: &[String]) -> Result<(), String> {
    let mut engine = open()?;
    let creds = engine
        .sync(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    icp_core::vault::save(&creds).map_err(|e| e.to_string())?;
    println!("{} credentials", creds.len());
    Ok(())
}

fn cmd_show(args: &[String]) -> Result<(), String> {
    let query = args.get(2).map(|s| s.to_lowercase()).unwrap_or_default();
    let creds = icp_core::vault::load().map_err(|e| e.to_string())?;
    let mut shown = 0;
    for c in &creds {
        let hay = format!("{} {} {}", c.domain, c.title, c.username).to_lowercase();
        if !query.is_empty() && !hay.contains(&query) {
            continue;
        }
        println!("{:<40}  {}", c.domain, c.username);
        shown += 1;
    }
    println!("{shown} of {} credentials", creds.len());
    Ok(())
}

fn cmd_add(args: &[String]) -> Result<(), String> {
    let domain = args.get(2).cloned().ok_or("no domain given")?;
    let username = args.get(3).cloned().ok_or("no username given")?;
    let password = args.get(4).cloned().ok_or("no password given")?;
    let mut engine = open()?;
    let outcome = engine
        .add_password(&domain, &username, &password, None, None, "Passwords")
        .map_err(|e| e.to_string())?;
    println!("saved (record {})", outcome.record_name);
    Ok(())
}

fn cmd_dump() -> Result<(), String> {
    let mut engine = open()?;
    let creds = engine
        .sync(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    let mut lines: Vec<String> = creds
        .iter()
        .map(|c| format!("{}|{}|{}", c.domain, c.username, c.password))
        .collect();
    lines.sort();
    for l in lines {
        println!("{l}");
    }
    Ok(())
}

fn cmd_update(args: &[String]) -> Result<(), String> {
    let record = args.get(2).cloned().ok_or("no record name given")?;
    let password = args.get(3).cloned().ok_or("no password given")?;
    let mut engine = open()?;
    let outcome = engine
        .update_password(&record, &password, None, None, "Passwords")
        .map_err(|e| e.to_string())?;
    println!("updated (record {})", outcome.record_name);
    Ok(())
}

fn cmd_delete(args: &[String]) -> Result<(), String> {
    let record = args.get(2).cloned().ok_or("no record name given")?;
    let mut engine = open()?;
    engine
        .delete_password(&record, "Passwords")
        .map_err(|e| e.to_string())?;
    println!("deleted (record {record})");
    Ok(())
}

fn cmd_check() -> Result<(), String> {
    let mut engine = open()?;
    println!(
        "peer:      {}",
        engine.peer_id().map_err(|e| e.to_string())?
    );
    println!(
        "user id:   {}",
        engine.user_id().map_err(|e| e.to_string())?
    );
    let (tlks, synckeys) = engine.fetch_view_keys().map_err(|e| e.to_string())?;
    println!(
        "view keys: {} TLKs, {} synckeys",
        tlks.len(),
        synckeys.len()
    );
    let records = engine
        .fetch_zones(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    let mut by_type: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in &records {
        *by_type.entry(r.record_type.as_str()).or_default() += 1;
    }
    println!("records:   {by_type:?}");
    let creds = engine
        .sync(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    println!("credentials: {}", creds.len());
    let with_code = creds.iter().filter(|c| !c.totp.is_empty()).count();
    println!("with a verification code: {with_code}");
    for c in creds.iter().filter(|c| !c.totp.is_empty()).take(3) {
        println!("   {} @ {} -> {}", c.username, c.domain, c.totp);
    }
    print!("sample:");
    for c in creds.iter().take(3) {
        print!(" {}@{}", c.username, c.domain);
    }
    println!();
    let _ = std::io::stdout().flush();
    Ok(())
}

/// Used by the tests: a stable summary of a credential list.
pub fn summarize(creds: &[Credential]) -> String {
    creds
        .iter()
        .map(|c| format!("{}|{}", c.domain, c.username))
        .collect::<Vec<_>>()
        .join("\n")
}
