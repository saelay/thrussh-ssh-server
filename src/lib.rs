/* simple SSH server implementation */

use std::str;
use std::process;

struct ShellSession<'a>(&'a mut Shell, &'a mut thrussh::server::Session, thrussh::ChannelId);

impl<'a> vte::Perform for ShellSession<'a> {
    /* character */
    fn print(&mut self, ch: char) {
        log::trace!("call print(ch: {})", ch);
        match ch {
            '\u{007f}' => {}, /* DEL */
            ch => {
                if self.0.cmdbuf_pos < self.0.cmdbuf.len() {
                    self.0.cmdbuf[self.0.cmdbuf_pos] = ch;
                    self.0.cmdbuf_pos = self.0.cmdbuf_pos + 1;
                    self.1.data(self.2, thrussh::CryptoVec::from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes()));
                }
            }
        }
    }

    /* C0 or C1 control function */
    fn execute(&mut self, byte: u8) {
        log::trace!("call execute(byte: {:02x})", byte);

        match byte {
            0x04 => { /* EOT(Ctrl+d) */
                /* write CRLF */
                self.1.data(self.2, thrussh::CryptoVec::from_slice(&[0x0d, 0x0a]));
                
                self.1.close(self.2);
            }
            0x08 => {/* BS */
                if self.0.cmdbuf_pos > 0 {
                    self.0.cmdbuf_pos = self.0.cmdbuf_pos - 1;
                    /* write BS */
                    self.1.data(self.2, thrussh::CryptoVec::from_slice(&[0x08]));
                    
                    /* write ECH */
                    self.1.data(self.2, thrussh::CryptoVec::from_slice(&[0x1b, 0x5b, 0x58]));
                }
            }
            0x0d => {/* CR */
                if self.0.cmdbuf_pos == 0 {
                }
                else {
                    /* execute command */
                    let cmdstr: String = self.0.cmdbuf[..self.0.cmdbuf_pos].iter()
                        .map(|ch| ch.encode_utf8(&mut[0;4]).to_owned())
                        .collect();
                    let mut tokens: Vec<&str> = cmdstr.split_whitespace().collect();
                    if tokens.len() > 0 {

                        /* write CRLF */
                        self.1.data(self.2, thrussh::CryptoVec::from_slice(&[0x0d, 0x0a]));
                            
                        if tokens[0] == "exit" {
                            self.1.close(self.2);
                        }
                        else {
                            log::trace!("exec command {:?}", tokens);
    
                            let output = if cfg!(target_os = "windows") {
                                let mut args = vec!["/C"];
                                args.append(&mut tokens);
                                process::Command::new("cmd")
                                    .args(&args)
                                    .output()
                            }
                            else {
                                let mut args = vec!["-c"];
                                args.append(&mut tokens);
                                process::Command::new("sh")
                                    .args(&args)
                                    .output()
                            };
    
                            match output {
                                Ok(output) => {
                                    let s = String::from_utf8_lossy(&output.stdout);
                                    self.1.data(self.2, thrussh::CryptoVec::from_slice(s.as_bytes()));
                                }
                                Err(e) => {
                                    let s = format!("Command Error: {:?}", e);
                                    self.1.data(self.2, thrussh::CryptoVec::from_slice(s.as_bytes()));
                                }
                            }
                        }
                    }

                    self.0.cmdbuf_pos = 0;
                }

                /* write CRLF */
                self.1.data(self.2, thrussh::CryptoVec::from_slice(&[0x0d, 0x0a]));
                /* write prompt */
                self.1.data(self.2, thrussh::CryptoVec::from_slice(self.0.prompt().as_bytes()));
            }
            _ => {/* not supported */}
        }
    }

    /* device control string */
    fn hook(&mut self, params: &vte::Params, intermediates: &[u8], ignore: bool, action: char) {
        log::trace!("call hook(params: {:?}, intermediates: {:?}, ignore: {}, action: {}", params, intermediates, ignore, action);
    }

    /* device control string */
    fn put(&mut self, byte: u8) {
        log::trace!("call put(byte: {:02x})", byte);
    }

    /* device control string */
    fn unhook(&mut self) {
        log::trace!("call unhook()");
    }

    /* OSC */
    fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
        log::trace!("call osc_dispatch(params: {:?}, bell_terminated: {})", params, bell_terminated);
    }

    /* CSI */
    fn csi_dispatch(&mut self, params: &vte::Params, intermediates: &[u8], ignore: bool, action: char) {
        log::trace!("call csi_diapatch(params: {:?}, intermediate: {:?}, ignore: {}, action: {}", params, intermediates, ignore, action);
    }

    /* ESC */
    fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
        log::trace!("call esc_dispatch(intermediates: {:?}, ignore: {}, byte: {:02x}", intermediates, ignore, byte);
    }
}

struct Shell {
    prompt: &'static str,
    cmdbuf: [char; 128],
    cmdbuf_pos: usize,
}



impl Shell {
    pub fn init(&mut self, channel: thrussh::ChannelId, session: &mut thrussh::server::Session) {
        session.data(channel, thrussh::CryptoVec::from_slice(self.prompt.as_bytes()));
    }

    pub fn prompt(&self) -> &'static str {
        self.prompt
    }
}

pub struct Server {
    shell: Shell,
    vte: vte::Parser,
}

impl Server {
    pub fn new() -> Self {
        Self {
            shell: Shell { prompt: "ssh> ", cmdbuf: ['\u{0000}'; 128], cmdbuf_pos: 0 },
            vte: vte::Parser::new(),
        }
    }
}

impl thrussh::server::Handler for Server {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, thrussh::server::Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, thrussh::server::Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, thrussh::server::Session, bool), anyhow::Error>>;

    
    fn finished_auth(self, auth: thrussh::server::Auth) -> Self::FutureAuth {
        log::trace!("call finished_auth(auth: {:?})", auth);
        futures::future::ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, s: thrussh::server::Session) -> Self::FutureBool {
        log::trace!("call finished_bool(b: {}, s) ", b);
        futures::future::ready(Ok((self, s, b)))
    }
    fn finished(self, s: thrussh::server::Session) -> Self::FutureUnit {
        log::trace!("call finished(s)");
        futures::future::ready(Ok((self, s)))
    }

    fn channel_open_session(self, channel: thrussh::ChannelId, session: thrussh::server::Session) -> Self::FutureUnit {
        log::trace!("call channel_open_session(channel: {:?}), s)", channel);
        self.finished(session)
    }

    fn auth_publickey(self, s: &str, k: &thrussh_keys::key::PublicKey) -> Self::FutureAuth {
        log::trace!("call auth_publickey(s: {}, k: {:?})", s, k);

        // TODO: implement password authentication
        // always accepted
        self.finished_auth(thrussh::server::Auth::Accept)
    }

    fn auth_none(self, user: &str) -> Self::FutureAuth {
        log::trace!("call auth_none(user: {})", user);

        // TODO: implement password authentication
        // always accepted
        self.finished_auth(thrussh::server::Auth::Accept)
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        log::trace!("call auth_password(user: {}, password: {})", user, password);

        // TODO: implement password authentication
        if password == "password123" {
            self.finished_auth(thrussh::server::Auth::Accept)
        }
        else {
            self.finished_auth(thrussh::server::Auth::Reject)
        }
    }

    fn data(mut self, channel: thrussh::ChannelId, data: &[u8], mut session: thrussh::server::Session) -> Self::FutureUnit {
        log::trace!("call data(channel: {:?}, data: {:?}, s)", channel, data);

        for d in data {
            self.vte.advance(
                &mut ShellSession{0: &mut self.shell, 1: &mut session, 2:channel},
                *d
            );
        }
        self.finished(session)
    }

    fn pty_request(
        self,
        channel: thrussh::ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(thrussh::Pty, u32)],
        session: thrussh::server::Session,
    ) -> Self::FutureUnit {
        log::trace!("call pty_request(channel: {:?}, term: {:?}, col_width: {:?}, row_width: {:?}, pix_width: {:?}, pix_height: {:?}, modes: {:?}, s)", channel, term, col_width, row_height, pix_width, pix_height, modes);
        self.finished(session)
    }
        
    fn shell_request(mut self, channel: thrussh::ChannelId, mut session: thrussh::server::Session) -> Self::FutureUnit {
        log::trace!("call shell_request(channel: {:?}, s)", channel);
        self.shell.init(channel, &mut session);
        self.finished(session)
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    fn exec_request(self, channel: thrussh::ChannelId, data: &[u8], session: thrussh::server::Session) -> Self::FutureUnit {
        log::trace!("call exec_request(channel: {:?}, data: {:?}, s)", channel, str::from_utf8(data).unwrap());
        self.finished(session)
    }
}
