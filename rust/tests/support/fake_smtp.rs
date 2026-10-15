//! A scripted fake SMTP server for the tests (PLAN.md 7.1), shared by the
//! unit tests (`src/smtp_tests.rs`) and the process tests (`binary.rs`).
//!
//! A scenario is the JSON of `fixtures/smtp_outcomes.json` (and of the S1b
//! spike's `scripted_smtp.py`): a reply code per phase (`banner`, `ehlo`,
//! `ehlo_tls`, `starttls`, `auth`, `mail`, `data`, `data_end`, `quit`;
//! `auth_plain` and `auth_login` for one mechanism), a code per recipient
//! local part (`rcpt`), the offered extensions
//! (`offer_starttls`, `auth_offer`) and faults per phase (`garbage`: a reply
//! without a code, `close`: the server closes, `hang`: no reply). STARTTLS
//! uses `rcgen` certificates with key identifiers (Python's
//! `VERIFY_X509_STRICT` needs them, S1b). Every session is recorded:
//! commands (`C:`, AUTH redacted), replies (`S:`), the envelope and the
//! un-stuffed message.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// One recorded SMTP session.
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// `C: <command>` and `S: <reply>` lines in order.
    pub log: Vec<String>,
    pub mail_from: Option<String>,
    /// The accepted recipients a message was sent for.
    pub data_for: Option<Vec<String>>,
    pub message: Option<Vec<u8>>,
    pub tls: bool,
}

impl Session {
    /// The command verbs the client sent.
    pub fn commands(&self) -> Vec<String> {
        self.log
            .iter()
            .filter_map(|line| line.strip_prefix("C: "))
            .map(|line| line.split(' ').next().unwrap_or_default().to_uppercase())
            .collect()
    }
}

/// The server's certificates.
pub struct Pki {
    /// The test CA (PEM), for `SMTP_CA_FILE`.
    pub ca_pem: String,
    /// `localhost` and `127.0.0.1`, issued by the test CA.
    pub good: Arc<ServerConfig>,
    /// `other.test`, issued by the test CA.
    pub wrong_name: Arc<ServerConfig>,
    /// `localhost`, self-signed (an unknown CA).
    pub unknown_ca: Arc<ServerConfig>,
}

impl Pki {
    pub fn new() -> Pki {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        };
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "mailgun-relay test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf = |names: &[&str], issuer: Option<&Issuer<'_, KeyPair>>| {
            let mut params =
                CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                    .unwrap();
            params.distinguished_name.push(DnType::CommonName, names[0]);
            params.use_authority_key_identifier_extension = true;
            let key = KeyPair::generate().unwrap();
            let cert = match issuer {
                Some(issuer) => params.signed_by(&key, issuer).unwrap(),
                None => params.self_signed(&key).unwrap(),
            };
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
            server_config(vec![cert.der().clone()], key)
        };
        Pki {
            ca_pem: ca.pem(),
            good: leaf(&["localhost", "127.0.0.1"], Some(&issuer)),
            wrong_name: leaf(&["other.test"], Some(&issuer)),
            unknown_ca: leaf(&["localhost"], None),
        }
    }

    pub fn by_name(&self, name: &str) -> Arc<ServerConfig> {
        match name {
            "good" => Arc::clone(&self.good),
            "wrongname" => Arc::clone(&self.wrong_name),
            "selfsigned" => Arc::clone(&self.unknown_ca),
            other => panic!("unknown certificate {other}"),
        }
    }
}

fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    Arc::new(config)
}

/// The scenario with the spike's defaults.
#[derive(Debug, Clone)]
pub struct Script {
    codes: HashMap<String, u16>,
    rcpt: HashMap<String, u16>,
    faults: HashMap<String, String>,
    offer_starttls: bool,
    auth_offer: String,
    auth_by_mechanism: HashMap<String, u16>,
}

impl Script {
    pub fn new(scenario: &Value) -> Script {
        let mut codes: HashMap<String, u16> = [
            ("banner", 220),
            ("ehlo", 250),
            ("ehlo_tls", 250),
            ("starttls", 220),
            ("auth", 235),
            ("mail", 250),
            ("data", 354),
            ("data_end", 250),
            ("quit", 221),
        ]
        .into_iter()
        .map(|(phase, code)| (phase.to_owned(), code))
        .collect();
        let mut script = Script {
            codes: HashMap::new(),
            rcpt: HashMap::new(),
            faults: HashMap::new(),
            offer_starttls: true,
            auth_offer: "PLAIN LOGIN".to_owned(),
            auth_by_mechanism: HashMap::new(),
        };
        for (key, value) in scenario.as_object().expect("a scenario object") {
            match key.as_str() {
                "offer_starttls" => script.offer_starttls = value.as_bool().unwrap(),
                "auth_offer" => value.as_str().unwrap().clone_into(&mut script.auth_offer),
                "rcpt" => {
                    for (local, code) in value.as_object().unwrap() {
                        script
                            .rcpt
                            .insert(local.clone(), code.as_u64().unwrap() as u16);
                    }
                }
                "fault" => {
                    for (phase, fault) in value.as_object().unwrap() {
                        script
                            .faults
                            .insert(phase.clone(), fault.as_str().unwrap().to_owned());
                    }
                }
                // A code for one AUTH mechanism only.
                "auth_plain" | "auth_login" => {
                    script
                        .auth_by_mechanism
                        .insert(key[5..].to_uppercase(), value.as_u64().unwrap() as u16);
                }
                phase if codes.contains_key(phase) => {
                    codes.insert(phase.to_owned(), value.as_u64().unwrap() as u16);
                }
                other => panic!("unknown scenario key {other}"),
            }
        }
        script.codes = codes;
        script
    }

    fn code(&self, phase: &str) -> u16 {
        self.codes[phase]
    }
}

/// A running fake server on `127.0.0.1`.
pub struct FakeSmtp {
    pub port: u16,
    pub sessions: Arc<Mutex<Vec<Session>>>,
}

impl FakeSmtp {
    /// Serve the scenario on the current tokio runtime.
    pub async fn start(scenario: &Value, tls: Option<Arc<ServerConfig>>) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Script::new(scenario));
        let recorded = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let script = Arc::clone(&script);
                let tls = tls.clone();
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let index = {
                        let mut sessions = recorded.lock().unwrap();
                        sessions.push(Session::default());
                        sessions.len() - 1
                    };
                    let io: Box<dyn Io> = Box::new(tcp);
                    let mut handler = Handler {
                        script: &script,
                        tls,
                        sessions: &recorded,
                        index,
                        stream: BufReader::new(io),
                        rcpts: Vec::new(),
                    };
                    handler.serve().await;
                });
            }
        });
        FakeSmtp { port, sessions }
    }

    /// Serve the scenario on a runtime in a thread of its own (process
    /// tests, which have no runtime).
    pub fn start_in_thread(scenario: Value, tls: Option<Arc<ServerConfig>>) -> FakeSmtp {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                sender.send(FakeSmtp::start(&scenario, tls).await).unwrap();
                std::future::pending::<()>().await;
            });
        });
        receiver.recv().unwrap()
    }

    pub fn sessions(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().clone()
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Handler<'a> {
    script: &'a Script,
    tls: Option<Arc<ServerConfig>>,
    sessions: &'a Mutex<Vec<Session>>,
    index: usize,
    stream: BufReader<Box<dyn Io>>,
    rcpts: Vec<String>,
}

impl Handler<'_> {
    fn record(&self, change: impl FnOnce(&mut Session)) {
        change(&mut self.sessions.lock().unwrap()[self.index]);
    }

    fn log(&self, line: String) {
        self.record(|s| s.log.push(line));
    }

    async fn write(&mut self, text: &str) -> bool {
        let stream = self.stream.get_mut();
        stream.write_all(text.as_bytes()).await.is_ok() && stream.flush().await.is_ok()
    }

    /// The reply of a phase, or its fault; `false` ends the session.
    async fn reply(&mut self, phase: &str, code: u16, lines: &[String]) -> bool {
        match self.script.faults.get(phase).map(String::as_str) {
            Some("close") => {
                self.log(format!("S: <close at {phase}>"));
                return false;
            }
            Some("hang") => {
                self.log(format!("S: <hang at {phase}>"));
                std::future::pending::<()>().await;
            }
            Some("garbage") => {
                self.log("S: garbage reply".to_owned());
                return self.write("garbage reply\r\n").await;
            }
            Some(other) => panic!("unknown fault {other}"),
            None => {}
        }
        let mut text = String::new();
        for (i, line) in lines.iter().enumerate() {
            let separator = if i + 1 == lines.len() { ' ' } else { '-' };
            text.push_str(&format!("{code}{separator}{line}\r\n"));
            self.log(format!("S: {code}{separator}{line}"));
        }
        // 421: the server closes the transmission channel.
        self.write(&text).await && code != 421
    }

    async fn simple(&mut self, phase: &str, text: &str) -> bool {
        let code = self.script.code(phase);
        self.reply(phase, code, &[text.to_owned()]).await
    }

    async fn read_line(&mut self) -> Option<String> {
        let mut line = Vec::new();
        match self.stream.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(
                String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
            ),
        }
    }

    fn ehlo_lines(&self, tls: bool) -> Vec<String> {
        let mut lines: Vec<String> = ["fake.test", "PIPELINING", "SIZE 52428800", "8BITMIME"]
            .map(str::to_owned)
            .to_vec();
        if !tls && self.script.offer_starttls {
            lines.push("STARTTLS".to_owned());
        }
        if (tls || !self.script.offer_starttls) && !self.script.auth_offer.is_empty() {
            lines.push(format!("AUTH {}", self.script.auth_offer));
        }
        lines
    }

    async fn serve(&mut self) {
        if !self.simple("banner", "fake.test ESMTP").await {
            return;
        }
        let mut tls = false;
        loop {
            let Some(line) = self.read_line().await else {
                self.log("C: <eof>".to_owned());
                return;
            };
            let verb = line.split(' ').next().unwrap_or_default().to_uppercase();
            self.log(format!(
                "C: {}",
                if verb == "AUTH" {
                    "AUTH <redacted>"
                } else {
                    &line
                }
            ));
            let go_on = match verb.as_str() {
                "EHLO" | "HELO" => {
                    let phase = if tls { "ehlo_tls" } else { "ehlo" };
                    let code = self.script.code(phase);
                    let lines = if code == 250 {
                        self.ehlo_lines(tls)
                    } else {
                        vec!["no".to_owned()]
                    };
                    self.reply(phase, code, &lines).await
                }
                "STARTTLS" => {
                    let ok = self.simple("starttls", "go ahead").await;
                    if ok && self.script.code("starttls") == 220 {
                        let config = self.tls.clone().expect("STARTTLS needs certificates");
                        let io = std::mem::replace(
                            &mut self.stream,
                            BufReader::new(Box::new(tokio::io::empty()) as Box<dyn Io>),
                        )
                        .into_inner();
                        match TlsAcceptor::from(config).accept(io).await {
                            Ok(stream) => {
                                self.stream = BufReader::new(Box::new(stream));
                                tls = true;
                                self.record(|s| s.tls = true);
                                self.log("S: <tls established>".to_owned());
                            }
                            Err(_) => {
                                self.log("S: <tls failed>".to_owned());
                                return;
                            }
                        }
                    }
                    ok
                }
                "AUTH" => self.auth(&line).await,
                "MAIL" => {
                    let from = line.split_once(':').map_or("", |(_, a)| a.trim());
                    let from = from.trim_start_matches('<').split('>').next().unwrap_or("");
                    let from = from.to_owned();
                    self.record(|s| s.mail_from = Some(from));
                    self.simple("mail", "sender result").await
                }
                "RCPT" => {
                    let address = line.split_once(':').map_or("", |(_, a)| a.trim());
                    let address = address.trim_matches(['<', '>']).to_owned();
                    let local = address.split('@').next().unwrap_or_default();
                    let code = self.script.rcpt.get(local).copied().unwrap_or(250);
                    if code == 250 {
                        self.rcpts.push(address.clone());
                    }
                    self.reply("rcpt", code, &["rcpt result".to_owned()]).await
                }
                "DATA" => {
                    let ok = self.simple("data", "send data").await;
                    if ok
                        && self.script.code("data") == 354
                        && !self.script.faults.contains_key("data")
                    {
                        let Some(message) = self.read_message().await else {
                            return;
                        };
                        let rcpts = self.rcpts.clone();
                        self.log(format!("D: <message {} bytes>", message.len()));
                        self.record(|s| {
                            s.data_for = Some(rcpts);
                            s.message = Some(message);
                        });
                        self.simple("data_end", "queued").await
                    } else {
                        ok
                    }
                }
                "RSET" => {
                    self.rcpts.clear();
                    self.reply("rset", 250, &["reset".to_owned()]).await
                }
                "QUIT" => {
                    self.simple("quit", "bye").await;
                    return;
                }
                _ => {
                    self.reply("other", 502, &["not implemented".to_owned()])
                        .await
                }
            };
            if !go_on {
                return;
            }
        }
    }

    async fn auth(&mut self, line: &str) -> bool {
        let parts: Vec<&str> = line.split(' ').collect();
        let mechanism = parts.get(1).map(|m| m.to_uppercase()).unwrap_or_default();
        if mechanism == "LOGIN" {
            let prompts: &[&str] = if parts.len() == 3 {
                &["UGFzc3dvcmQ6"]
            } else {
                &["VXNlcm5hbWU6", "UGFzc3dvcmQ6"]
            };
            for prompt in prompts {
                if !self.write(&format!("334 {prompt}\r\n")).await
                    || self.read_line().await.is_none()
                {
                    return false;
                }
            }
        } else if parts.len() == 2
            && (!self.write("334 \r\n").await || self.read_line().await.is_none())
        {
            return false;
        }
        self.record(|s| s.log.push(format!("S: <auth {mechanism}>")));
        let code = (self.script.auth_by_mechanism.get(&mechanism).copied())
            .unwrap_or_else(|| self.script.code("auth"));
        self.reply("auth", code, &["auth result".to_owned()]).await
    }

    /// The message up to the lone dot, un-stuffed, with its CRLFs.
    async fn read_message(&mut self) -> Option<Vec<u8>> {
        let mut message = Vec::new();
        loop {
            let mut line = Vec::new();
            match self.stream.read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => return None,
                Ok(_) => {}
            }
            if line == b".\r\n" {
                return Some(message);
            }
            let line = line.strip_prefix(b".").unwrap_or(&line);
            message.extend_from_slice(line);
        }
    }
}

/// Read everything a client sends until it closes (a sink for tests).
pub async fn drain(mut stream: impl AsyncRead + Unpin) {
    let mut buffer = [0u8; 4096];
    while matches!(stream.read(&mut buffer).await, Ok(n) if n > 0) {}
}
