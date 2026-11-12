//! The command-line face of the client: sync, show, add.

use std::io::Write;

use icp_core::engine::Engine;
use icp_core::keychain::Credential;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = match command {
        "sync" => cmd_sync(&args),
        "groups" => cmd_groups(&args),
        "aliases" => cmd_aliases(&args),
        "show" => cmd_show(&args),
        "add" => cmd_add(&args),
        "check" => cmd_check(),
        "status" => cmd_status(&args),
        "diag" => cmd_diag(&args),
        "logout" => cmd_logout(&args),
        "dump" => cmd_dump(),
        "update" => cmd_update(&args),
        "delete" => cmd_delete(&args),
        "login" => cmd_login(&args),
        "join" => cmd_join(&args),
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
  groups          the shared password groups
  aliases         the Hide My Email aliases
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
        .sync_with_groups(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    icp_core::vault::save(&creds).map_err(|e| e.to_string())?;
    println!("{} credentials", creds.len());
    Ok(())
}

/// The Hide My Email aliases: refreshed from Apple, then cached.
fn cmd_aliases(args: &[String]) -> Result<(), String> {
    use icp_core::hme;
    use icp_core::webauth;
    use icp_core::{login::ask, session};

    let mut record = session::load()
        .map_err(|e| e.to_string())?
        .ok_or("not signed in - run `icp login` first")?;
    let refresh = !args.iter().any(|a| a == "--cached");
    if !refresh {
        for alias in hme::load() {
            println!(
                "{:<32} {:<20} -> {}",
                alias.address, alias.label, alias.forward_to
            );
        }
        return Ok(());
    }
    let (mut session, account) = webauth::ensure_session(&mut record, || {
        let code = ask("6-digit code: ");
        if code.is_empty() {
            return Err(icp_core::Error::Apple("no code given".into()));
        }
        Ok(code)
    })
    .map_err(|e| e.to_string())?;
    session::save(&record).map_err(|e| e.to_string())?;
    let base = webauth::extract_webservices(&account)
        .get("premiummailsettings")
        .cloned()
        .ok_or("this account has no Hide My Email service")?;
    let aliases = hme::list(&mut session, &base).map_err(|e| e.to_string())?;
    hme::save(&aliases).map_err(|e| e.to_string())?;
    for alias in &aliases {
        println!(
            "{:<32} {:<20} -> {}",
            alias.address, alias.label, alias.forward_to
        );
    }
    println!("{} aliases", aliases.len());
    Ok(())
}

/// The shared groups, and what they hold.
fn cmd_groups(_args: &[String]) -> Result<(), String> {
    let mut engine = open()?;
    let items = engine
        .sync_items(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    let groups = engine.fetch_groups(&items).map_err(|e| e.to_string())?;
    if groups.is_empty() {
        println!("no shared groups");
        return Ok(());
    }
    for group in groups {
        let logins = group.credentials();
        println!(
            "{:<28} items={:<4} logins={:<4}",
            group.label(),
            group.items.len(),
            logins.len()
        );
        for credential in logins {
            println!("    {:<36}  {}", credential.domain, credential.username);
        }
    }
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

fn cmd_login(args: &[String]) -> Result<(), String> {
    use icp_core::login::{ask, ask_secret, sign_in};
    use icp_core::{anisette::Anisette, device::Device};

    let device = Device::load_or_create().map_err(|e| e.to_string())?;
    let url =
        std::env::var("ICP_ANISETTE_URL").unwrap_or_else(|_| "http://127.0.0.1:6969".to_string());
    let mut anisette = Anisette::new(&url).map_err(|e| e.to_string())?;

    let username = ask("Apple ID: ");
    if username.is_empty() {
        return Err("no Apple ID given".into());
    }
    let password = ask_secret("Password: ");
    if password.is_empty() {
        return Err("no password given".into());
    }

    let mut twofa = |kind: &str| -> Result<String, icp_core::Error> {
        let where_ = if kind == "sms" {
            "your phone by SMS"
        } else {
            "your trusted devices"
        };
        println!("Apple sent a code to {where_}.");
        let code = ask("6-digit code: ");
        if code.is_empty() {
            return Err(icp_core::Error::Apple("no code given".into()));
        }
        Ok(code)
    };

    let login = sign_in(&username, &password, &mut anisette, &device, &mut twofa)
        .map_err(|e| e.to_string())?;

    // The session: the tokens, the device identity and (optionally) the password.
    let mut record = icp_core::session::load()
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    if !record.is_object() {
        record = serde_json::Value::Object(Default::default());
    }
    let object = record.as_object_mut().unwrap();
    object.insert(
        "username".into(),
        serde_json::Value::String(username.clone()),
    );
    // The password is kept (encrypted, in the session file) so the web session
    // can be established without asking for it again.
    if !args.iter().any(|a| a == "--no-save-password") {
        object.insert(
            "password".into(),
            serde_json::Value::String(password.clone()),
        );
    }
    object.insert("dsid".into(), serde_json::Value::String(login.dsid.clone()));
    object.insert(
        "dsid_numeric".into(),
        serde_json::Value::String(login.dsid.clone()),
    );
    let mut mme = serde_json::Map::new();
    mme.insert("dsid".into(), serde_json::Value::String(login.dsid.clone()));
    mme.insert(
        "mmeAuthToken".into(),
        serde_json::Value::String(login.mme_auth_token.clone()),
    );
    mme.insert(
        "cloudKitUserId".into(),
        serde_json::Value::String(login.cloudkit_user_id.clone()),
    );
    let mut tokens = serde_json::Map::new();
    tokens.insert(
        "cloudKitToken".into(),
        serde_json::Value::String(login.cloudkit_token.clone()),
    );
    mme.insert("tokens".into(), serde_json::Value::Object(tokens));
    object.insert("mme".into(), serde_json::Value::Object(mme));
    let mut ws = serde_json::Map::new();
    for (name, url) in &login.webservices {
        if !url.is_empty() {
            ws.insert(name.clone(), serde_json::Value::String(url.clone()));
        }
    }
    object.insert("webservices".into(), serde_json::Value::Object(ws));

    icp_core::session::save(&record).map_err(|e| e.to_string())?;
    println!("Signed in as {username}.");

    // The first sync: it works right away when the trust circle is already
    // joined, and says what to do when it is not.
    match icp_core::engine::Engine::open(None).and_then(|mut engine| {
        let creds = engine.sync_with_groups(icp_core::ckks::KEYCHAIN_ZONES)?;
        icp_core::vault::save(&creds)?;
        Ok(creds.len())
    }) {
        Ok(count) => println!("{count} logins in the vault."),
        Err(e) => {
            println!("The keychain trust still has to be joined - run `icp join` for that.");
            println!("({e})");
        }
    }
    Ok(())
}

fn cmd_join(_args: &[String]) -> Result<(), String> {
    use icp_core::joinflow::ask;
    use icp_core::login::ask_secret as secret;
    use icp_core::{anisette::Anisette, device::Device, engine::Engine, session};

    let record = session::load()
        .map_err(|e| e.to_string())?
        .ok_or("not signed in - run `icp login` first")?;
    let username = record
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pet = record
        .get("pet")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let escrow_host = record
        .get("webservices")
        .and_then(|w| w.get("keychainsync"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if pet.is_empty() {
        return Err("the session has no token - run `icp login` again".into());
    }
    if escrow_host.is_empty() {
        return Err("the session has no escrow service - run `icp login` again".into());
    }

    let device = Device::load_or_create().map_err(|e| e.to_string())?;
    let url =
        std::env::var("ICP_ANISETTE_URL").unwrap_or_else(|_| "http://127.0.0.1:6969".to_string());
    let mut anisette = Anisette::new(&url).map_err(|e| e.to_string())?;

    println!("Looking for the escrow records of this account...");
    let bottles =
        icp_core::join::list_bottles(&escrow_host, &username, &pet, &device, &mut anisette)
            .map_err(|e| e.to_string())?;
    if bottles.is_empty() {
        return Err("no escrow records were found for this account".into());
    }
    for (label, meta) in &bottles {
        let name = meta
            .as_dictionary()
            .and_then(|d| d.get("ClientMetadata"))
            .and_then(|v| v.as_dictionary())
            .map(|d| {
                d.get("device_name")
                    .and_then(|v| v.as_string())
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default();
        println!("  {label}  {name}");
    }

    let passcode = secret("Passcode of the device to recover: ");
    if passcode.is_empty() {
        return Err("no passcode given".into());
    }
    println!("This spends one of the escrow service's ten attempts. The tenth wrong passcode");
    println!("destroys the record forever.");
    let confirm = ask("Type YES to continue: ");
    if confirm != "YES" {
        return Err("aborted - no attempt spent".into());
    }

    let mut client = Engine::open(Some(&url)).map_err(|e| e.to_string())?;
    let bottle_raw = bottles
        .first()
        .map(|(label, _)| label.clone())
        .unwrap_or_default();
    let peer_id = icp_core::joinflow::run(
        &mut client,
        &mut anisette,
        &device,
        &username,
        &pet,
        &escrow_host,
        bottle_raw.as_bytes(),
        &passcode,
        true,
    )
    .map_err(|e| e.to_string())?;
    println!("Joined the keychain as {peer_id}.");
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

/// The account's state: is it signed in, is it joined, how fresh is the vault.
fn cmd_status(_args: &[String]) -> Result<(), String> {
    let record = icp_core::session::load().map_err(|e| e.to_string())?;
    let Some(record) = record else {
        println!("signed in:   no - run `icp login`");
        return Ok(());
    };
    let username = record
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!("signed in:   yes ({username})");
    let octagon = record.get("octagon");
    let joined = octagon
        .and_then(|o| o.get("peer_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!(
        "joined:      {}",
        if joined.is_empty() {
            "no - run `icp join`"
        } else {
            "yes"
        }
    );
    if !joined.is_empty() {
        println!("peer:        {joined}");
    }
    let vault = icp_core::vault::load().unwrap_or_default();
    println!("logins:      {}", vault.len());
    if let Ok(meta) = std::fs::metadata(icp_core::device::vault_file()) {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = modified.elapsed() {
                println!("vault:       {} minutes old", age.as_secs() / 60);
            }
        }
    }
    let mme = record.get("mme");
    let token = mme
        .and_then(|m| m.get("tokens"))
        .and_then(|t| t.get("cloudKitToken"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!(
        "cloudkit token: {}",
        if token.is_empty() {
            "missing"
        } else {
            "present"
        }
    );
    Ok(())
}

/// The zones and what they hold.
fn cmd_diag(_args: &[String]) -> Result<(), String> {
    let mut engine = open()?;
    let records = engine
        .fetch_zones(icp_core::ckks::KEYCHAIN_ZONES)
        .map_err(|e| e.to_string())?;
    let mut by_type: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in &records {
        *by_type.entry(r.record_type.as_str()).or_default() += 1;
    }
    println!("zones:  {}", icp_core::ckks::KEYCHAIN_ZONES.len());
    for (kind, count) in by_type {
        println!("  {kind:<14} {count}");
    }
    println!("total records: {}", records.len());
    Ok(())
}

/// Forget the session (the device identity stays).
fn cmd_logout(_args: &[String]) -> Result<(), String> {
    icp_core::session::clear().map_err(|e| e.to_string())?;
    println!("Session cleared. The device identity is kept.");
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
