use std::sync::{Arc};

use thrussh::{MethodSet};

// private key (example)
// generated by puttygen (Parameter=ed25519),
// convert OPENSSH-key (Conversions->export OpenSSH key)
const SAMPLE_KEY: &'static str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCq
CH7Npj5v29J1b139sNNcAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAcs
lnU9Tmmv2Jc926KPGMnyfw2h8uW8H5ohqP2zZwpyAAAAoIJ0I6iA35JGfyl+wizY
RWSSkmBin6KE3w+ye9/YWic+oGXvngfM0lFj3fO0y+YWm50vw01C/xPmFsw2UN3F
KwtJFkziwI7jZVohdi5RanIL50/EWA8kumj33kW9YkrPM2dKx/Wa+URIXemAs5tw
yLdOuV5DkMbc5nf5rD11x9VWdp3FPFW53hI6FBBtLxKPHk33EsCbqixzml7gGnwE
GP0=
-----END OPENSSH PRIVATE KEY-----
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    log::info!("thrussh_ssh_server_example start");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:22").await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        /* new client */
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(6000*10));
        config.methods = MethodSet::PASSWORD; // allow password auth only
        let server_key = thrussh_keys::decode_secret_key(SAMPLE_KEY, Some("sample_key")).unwrap();
        config.keys.push(server_key);
        log::debug!("connect {}", addr);
        let server = thrussh_ssh_server::Server::new();
        tokio::spawn(thrussh::server::run_stream(
            Arc::new(config),
            stream,
            server,
        ));
        log::debug!("connection disconnect");
    }

    //log::info!("thrussh_ssh_server_example end");
    Ok(())
}