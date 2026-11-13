use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};

fn cli(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kakao-rust"))
        .arg("--data-dir")
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}
fn value(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn cli_requires_private_dir_and_supports_complete_offline_workflow() {
    let help = Command::new(env!("CARGO_BIN_EXE_kakao-rust"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let missing = Command::new(env!("CARGO_BIN_EXE_kakao-rust"))
        .arg("init")
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let dir = tempfile::Builder::new()
        .prefix("kakao-cli-")
        .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700))
        .tempdir()
        .unwrap();
    assert_eq!(
        value(cli(dir.path(), &["init"]))["native_auth"],
        "device_approval"
    );
    assert_eq!(
        value(cli(dir.path(), &["auth", "status"]))["state"],
        "not_started"
    );
    // Missing selected device rejects before any production network request.
    let auth_missing = cli(dir.path(), &["auth", "qr", "--timeout-seconds", "1"]);
    assert!(!auth_missing.status.success());
    assert!(String::from_utf8_lossy(&auth_missing.stderr).contains("DeviceRequired"));
    assert!(!dir.path().join(".qr-auth-lock").exists());
    assert!(
        !cli(dir.path(), &["auth", "qr", "--timeout-seconds", "601"])
            .status
            .success()
    );
    assert!(!cli(dir.path(), &["auth", "qr", "--timeout-seconds", "0"])
        .status
        .success());
    let catalog = concat!(env!("CARGO_MANIFEST_DIR"), "/config/device-catalog.json");
    let profile = value(cli(dir.path(), &["device", "init", "--catalog", catalog]));
    let persisted = value(cli(
        dir.path(),
        &[
            "device",
            "init",
            "--catalog",
            "/definitely-missing-kakao-catalog",
        ],
    ));
    assert_eq!(profile, persisted);
    assert_eq!(profile["native_auth_ready"], false);
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/synthetic.jsonl");
    assert_eq!(
        value(cli(dir.path(), &["import", "--file", fixture]))["changed"],
        4
    );
    assert_eq!(
        value(cli(dir.path(), &["import", "--file", fixture]))["replayed"],
        4
    );
    let cursor = value(cli(
        dir.path(),
        &[
            "cursor",
            "--account-id",
            "synthetic-account",
            "--stream-id",
            "demo",
        ],
    ));
    assert_eq!(cursor["position"], 4);
    // Room permission must be an explicit choice, preventing accidental broad tokens.
    assert!(!cli(
        dir.path(),
        &[
            "token",
            "issue",
            "--label",
            "test",
            "--account-id",
            "synthetic-account",
            "--scope",
            "messages:read"
        ]
    )
    .status
    .success());
    let issued = value(cli(
        dir.path(),
        &[
            "token",
            "issue",
            "--label",
            "test",
            "--account-id",
            "synthetic-account",
            "--scope",
            "messages:read,rooms:read",
            "--room",
            "demo-room",
        ],
    ));
    assert_eq!(issued["token"].as_str().unwrap().len(), 100);
    let list = value(cli(dir.path(), &["token", "list"]));
    assert!(list[0].get("token").is_none());
    assert!(list[0].get("token_hash").is_none());
    value(cli(
        dir.path(),
        &[
            "token",
            "revoke",
            "--id",
            issued["metadata"]["id"].as_str().unwrap(),
        ],
    ));
    assert!(value(cli(dir.path(), &["token", "list"]))[0]["revoked_at"].is_number());
    assert!(!cli(dir.path(), &["serve", "--bind", "0.0.0.0:0"])
        .status
        .success());
}
