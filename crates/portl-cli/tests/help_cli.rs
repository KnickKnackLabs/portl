#![allow(clippy::needless_raw_string_hashes, clippy::too_many_lines)]

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

fn help_output(args: &[&str]) -> String {
    let output = Command::cargo_bin("portl")
        .expect("cargo bin")
        .args(args)
        .output()
        .expect("run portl --help");
    assert!(
        output.status.success(),
        "expected success for {:?}, stderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn cli_help_lists_expected_top_level_commands() {
    let help = help_output(&["--help"]);
    for command in [
        "init", "doctor", "status", "shell", "exec", "tcp", "udp", "mint", "revoke", "install",
        "docker", "slicer", "gateway",
    ] {
        assert!(
            help.contains(command),
            "missing top-level command {command}\n{help}"
        );
    }
    assert!(
        !help.contains("mint-root"),
        "removed mint-root still shown\n{help}"
    );
}

#[test]
fn top_level_help_snapshots_match() {
    let cases = [
        (
            &["--help"][..],
            r#"portl CLI — multicall surface for `portl`, `portl-agent`, and `portl-gateway`.

Usage: portl <COMMAND>

Commands:
  init     Create identity, run doctor, and print next steps
  doctor   Print strictly local diagnostics (clock, identity, listener bind, discovery config,
           ticket expiry)
  status   Query peer reachability and metadata
  shell    Open an interactive remote PTY shell
  exec     Run a remote command without a PTY
  tcp      Set up one or more local TCP forwards
  udp      Set up one or more local UDP forwards
  mint     Mint a ticket with the local identity
  revoke   Append a local ticket revocation, optionally publish it, or list the current revocation
           log
  install  Install the daemon for a supported target
  docker   Docker target management
  slicer   Slicer target management
  gateway  Run the slicer HTTP bridge against an upstream API
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
"#,
        ),
        (
            &["init", "--help"][..],
            r#"Create identity, run doctor, and print next steps

Usage: portl init [OPTIONS]

Options:
      --force        
      --role <ROLE>  [possible values: operator, agent]
  -h, --help         Print help
"#,
        ),
        (
            &["doctor", "--help"][..],
            r#"Print strictly local diagnostics (clock, identity, listener bind, discovery config, ticket expiry)

Usage: portl doctor

Options:
  -h, --help  Print help
"#,
        ),
        (
            &["status", "--help"][..],
            r#"Query peer reachability and metadata

Usage: portl status [OPTIONS] <PEER>

Arguments:
  <PEER>  

Options:
      --relay  Also force the handshake over the peer's relay path
  -h, --help   Print help
"#,
        ),
        (
            &["shell", "--help"][..],
            r#"Open an interactive remote PTY shell

Usage: portl shell [OPTIONS] <PEER>

Arguments:
  <PEER>  

Options:
      --cwd <CWD>    
      --user <USER>  
  -h, --help         Print help
"#,
        ),
        (
            &["exec", "--help"][..],
            r#"Run a remote command without a PTY

Usage: portl exec [OPTIONS] <PEER> -- <ARGV>...

Arguments:
  <PEER>     
  <ARGV>...  

Options:
      --cwd <CWD>    
      --user <USER>  
  -h, --help         Print help
"#,
        ),
        (
            &["tcp", "--help"][..],
            r#"Set up one or more local TCP forwards

Usage: portl tcp -L <LOCAL> <PEER>

Arguments:
  <PEER>  

Options:
  -L <LOCAL>  
  -h, --help  Print help
"#,
        ),
        (
            &["udp", "--help"][..],
            r#"Set up one or more local UDP forwards

Usage: portl udp -L <LOCAL> <PEER>

Arguments:
  <PEER>  

Options:
  -L <LOCAL>  
  -h, --help  Print help
"#,
        ),
        (
            &["mint", "--help"][..],
            r#"Mint a ticket with the local identity

Usage: portl mint [OPTIONS] <CAPS>

Arguments:
  <CAPS>  

Options:
      --ttl <TTL>      [default: 30d]
      --to <TO>        
      --from <FROM>    
  -o, --print <PRINT>  [default: string] [possible values: string, qr, url]
  -h, --help           Print help
"#,
        ),
        (
            &["revoke", "--help"][..],
            r#"Append a local ticket revocation, optionally publish it, or list the current revocation log

Usage: portl revoke [OPTIONS] [ID]

Arguments:
  [ID]  

Options:
      --list     
      --publish  
  -h, --help     Print help
"#,
        ),
        (
            &["install", "--help"][..],
            r#"Install the daemon for a supported target

Usage: portl install [OPTIONS] [TARGET]

Arguments:
  [TARGET]  [possible values: systemd, launchd, dockerfile, openrc]

Options:
      --apply            
      --yes              
      --detect           
      --dry-run          
      --output <OUTPUT>  
  -h, --help             Print help
"#,
        ),
        (
            &["docker", "--help"][..],
            r#"Docker target management

Usage: portl docker <COMMAND>

Commands:
  run     
  attach  
  detach  
  list    
  rm      
  bake    
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
"#,
        ),
        (
            &["slicer", "--help"][..],
            r#"Slicer target management

Usage: portl slicer <COMMAND>

Commands:
  run   
  list  
  rm    
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
"#,
        ),
        (
            &["gateway", "--help"][..],
            r#"Run the slicer HTTP bridge against an upstream API

Usage: portl gateway <UPSTREAM_URL>

Arguments:
  <UPSTREAM_URL>  

Options:
  -h, --help  Print help
"#,
        ),
    ];

    for (args, expected) in cases {
        let actual = help_output(args);
        assert_eq!(actual, expected, "help snapshot mismatch for {args:?}");
    }
}

// ---- merged small CLI test files (per TEST_BUILD_TUNING.md) ----

mod doctor_cli {
    use anyhow::Result;
    use assert_cmd::Command;
    use portl_core::id::{Identity, store};
    use tempfile::tempdir;

    #[test]
    fn doctor_is_offline_safe() -> Result<()> {
        let home = tempdir()?;
        store::save(&Identity::new(), &home.path().join("identity.bin"))?;

        Command::cargo_bin("portl")?
            .env("PORTL_HOME", home.path())
            .env("PORTL_DISCOVERY", "none")
            .arg("doctor")
            .assert()
            .success();

        Ok(())
    }
}

mod gateway_cli {
    use std::process::Command;

    use anyhow::Result;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn portl_gateway_help_matches_top_level_gateway_help() -> Result<()> {
        let portl = assert_cmd::cargo::cargo_bin("portl");

        let direct = Command::new(&portl).args(["gateway", "--help"]).output()?;

        let temp = tempdir()?;
        let gateway = temp.path().join("portl-gateway");
        std::os::unix::fs::symlink(&portl, &gateway)?;

        let multicall = Command::new(&gateway).arg("--help").output()?;
        assert_eq!(multicall.status.code(), direct.status.code());
        assert_eq!(multicall.stdout, direct.stdout);
        assert_eq!(multicall.stderr, direct.stderr);

        Ok(())
    }
}

mod init_install_cli {
    use assert_cmd::cargo::CommandCargoExt;
    use portl_core::id::store::default_path_with_home;
    use std::process::Command;
    use tempfile::tempdir;

    #[test]
    fn init_generates_identity_and_runs_doctor() {
        let home = tempdir().expect("tempdir");
        let identity_path = default_path_with_home(Some(home.path()));

        let output = Command::cargo_bin("portl")
            .expect("cargo bin")
            .env("PORTL_HOME", home.path())
            .args(["init"])
            .output()
            .expect("run init");

        assert!(output.status.success(), "init failed: {:?}", output.status);
        assert!(identity_path.exists(), "identity was not created");

        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(
            stdout.contains("created identity:") || stdout.contains("using existing identity:")
        );
        assert!(stdout.contains("[ok  ]") || stdout.contains("[warn]"));
        assert!(stdout.contains("cookbook: portl docker run <image>"));
    }
}
