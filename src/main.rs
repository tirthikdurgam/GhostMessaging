mod stego;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures_lite::StreamExt;
use iroh::{Endpoint, NodeAddr, protocol::Router};
use iroh_gossip::{net::{Gossip, GossipEvent}, proto::TopicId};
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, fmt, str::FromStr, time::Duration};
use base64::Engine; 
use chrono::Local;

// --- UI Imports ---
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, BorderType, Paragraph, List, ListItem, Padding},
};

// --- DATA STRUCTURES ---
#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    nodes: Vec<NodeAddr>,
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let binary_data = bincode::serialize(self).map_err(|_| fmt::Error)?;
        let s = base64::engine::general_purpose::STANDARD_NO_PAD.encode(binary_data);
        write!(f, "{}", s)
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean_s = s.trim();
        let binary_data = base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean_s)?;
        let ticket = bincode::deserialize(&binary_data)?;
        Ok(ticket)
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    AboutMe { name: String },
    Chat { text: String },
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Host {
        #[arg(short, long, default_value = "Ghost")]
        name: String,
        #[arg(short, long, default_value = "Hello World")]
        cover: String, 
    },
    Join {
        #[arg(long)]
        ticket: String,
        #[arg(short, long, default_value = "Ghost")]
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let endpoint = Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await?;
    let gossip = Gossip::builder().spawn(endpoint.clone()).await?;
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn()
        .await?;

    match &args.command {
        Commands::Host { name, cover } => {
            let topic = TopicId::from_bytes(rand::random());
            let mut me = endpoint.node_addr().await?;
            let mut unique_ports = HashSet::new();
            for addr in &me.direct_addresses { unique_ports.insert(addr.port()); }
            for port in unique_ports {
                let localhost = std::net::SocketAddr::from_str(&format!("127.0.0.1:{}", port))?;
                me.direct_addresses.insert(localhost);
            }

            let ticket = Ticket { topic, nodes: vec![me] };
            let ghost_ticket = stego::hide(cover, &ticket.to_string());

            println!("\n--- 👻 GHOST TICKET ---");
            println!("{}", ghost_ticket);
            println!("-----------------------\n");
            println!("Press ENTER to Initialize...");
            
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;

            let (sender, receiver) = gossip.subscribe(topic, vec![])?.split();
            run_tui(sender, receiver, name.clone()).await?;
        }
        
        Commands::Join { ticket, name } => {
            let decoded = match stego::reveal(ticket) {
                Ok(s) => s,
                Err(_) => ticket.clone(),
            };
            let ticket = Ticket::from_str(&decoded).context("Invalid Ticket")?;
            
            let peer_ids: Vec<iroh::NodeId> = ticket.nodes.iter().map(|addr| addr.node_id).collect();
            for addr in ticket.nodes { endpoint.add_node_addr(addr)?; }

            println!("Connecting...");
            let connect_future = gossip.subscribe_and_join(ticket.topic, peer_ids);
            let topic_source = match tokio::time::timeout(Duration::from_secs(30), connect_future).await {
                Ok(res) => res?,
                Err(_) => {
                    println!("Connection Failed (Timeout)");
                    return Ok(());
                }
            };

            let (sender, receiver) = topic_source.split();
            run_tui(sender, receiver, name.clone()).await?;
        }
    }

    router.shutdown().await?;
    Ok(())
}

// --- MODERN UI LOGIC ---

struct ChatMessage {
    sender: String,
    text: String,
    time: String,
    is_me: bool,
}

struct AppState {
    messages: Vec<ChatMessage>, 
    input: String,
    peer_names: HashMap<iroh::NodeId, String>,
    my_name: String,
}

async fn run_tui(
    sender: iroh_gossip::net::GossipSender,
    mut receiver: iroh_gossip::net::GossipReceiver,
    my_name: String,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState {
        messages: Vec::new(),
        input: String::new(),
        peer_names: HashMap::new(),
        my_name: my_name.clone(),
    };

    // --- HEARTBEAT SYSTEM (Fixes "Unknown" Name Bug) ---
    // Sends "AboutMe" every 3 seconds so new peers learn our name immediately.
    let gossip_tx = sender.clone();
    let heartbeat_name = my_name.clone();
    tokio::spawn(async move {
        loop {
            let msg = Message::AboutMe { name: heartbeat_name.clone() };
            if let Ok(bytes) = serde_json::to_vec(&msg) {
                let _ = gossip_tx.broadcast(bytes.into()).await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });

    loop {
        terminal.draw(|f| ui(f, &state))?;

        tokio::select! {
            event = receiver.next() => {
                if let Some(Ok(iroh_gossip::net::Event::Gossip(GossipEvent::Received(msg)))) = event {
                    let from_id = msg.delivered_from;
                    if let Ok(decoded) = serde_json::from_slice::<Message>(&msg.content) {
                        match decoded {
                            Message::AboutMe { name } => {
                                state.peer_names.insert(from_id, name.clone());
                            }
                            Message::Chat { text } => {
                                let name = state.peer_names.get(&from_id).map(|s| s.as_str()).unwrap_or("Unknown");
                                let time = Local::now().format("%H:%M").to_string();
                                state.messages.push(ChatMessage {
                                    sender: name.to_string(),
                                    text,
                                    time,
                                    is_me: false,
                                });
                            }
                        }
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind == KeyEventKind::Press {
                            match key.code {
                                KeyCode::Enter => {
                                    if !state.input.is_empty() {
                                        let text = state.input.drain(..).collect::<String>();
                                        let msg = Message::Chat { text: text.clone() };
                                        if let Ok(bytes) = serde_json::to_vec(&msg) {
                                            let _ = sender.broadcast(bytes.into()).await;
                                        }
                                        let time = Local::now().format("%H:%M").to_string();
                                        state.messages.push(ChatMessage {
                                            sender: state.my_name.clone(),
                                            text,
                                            time,
                                            is_me: true,
                                        });
                                    }
                                }
                                KeyCode::Char(c) => { state.input.push(c); }
                                KeyCode::Backspace => { state.input.pop(); }
                                KeyCode::Esc => { break; }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn ui(frame: &mut Frame, state: &AppState) {
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(25), // Sidebar (Left)
            Constraint::Min(1),     // Chat (Right)
        ])
        .split(frame.area());

    let chat_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // Messages
            Constraint::Length(3), // Input
        ])
        .split(main_layout[1]);

    // --- SIDEBAR (PEERS) ---
    let mut peers: Vec<ListItem> = state.peer_names.values().map(|name| {
        ListItem::new(Line::from(vec![
            Span::styled(" ● ", Style::default().fg(Color::Cyan)), 
            Span::raw(name),
        ]))
    }).collect();
    
    peers.insert(0, ListItem::new(Line::from(vec![
        Span::styled(" ● ", Style::default().fg(Color::Green)), 
        Span::styled(format!("{} (You)", state.my_name), Style::default().add_modifier(Modifier::BOLD)),
    ])));

    let sidebar = List::new(peers)
        .block(Block::default()
            .borders(Borders::RIGHT) 
            .title(" Network ")
            .padding(Padding::new(1, 1, 1, 1)))
        .style(Style::default().fg(Color::DarkGray));
            
    frame.render_widget(sidebar, main_layout[0]);

    // --- CHAT MESSAGES (SMS Layout) ---
    let available_height = chat_layout[0].height as usize;
    let message_count = state.messages.len();
    let skip = if message_count > available_height { message_count - available_height } else { 0 };

    let mut chat_lines = Vec::new();
    
    for msg in state.messages.iter().skip(skip) {
        if msg.is_me {
            // RIGHT ALIGN (My Messages)
            let content = Line::from(vec![
                Span::styled(&msg.text, Style::default().fg(Color::White)),
                Span::styled(format!("  [{}]", msg.time), Style::default().fg(Color::DarkGray)),
            ]).alignment(Alignment::Right); 
            chat_lines.push(content);
        } else {
            // LEFT ALIGN (Their Messages)
            let content = Line::from(vec![
                Span::styled(&msg.sender, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(": "),
                Span::styled(&msg.text, Style::default().fg(Color::Gray)),
                Span::styled(format!("  [{}]", msg.time), Style::default().fg(Color::DarkGray)),
            ]).alignment(Alignment::Left);
            chat_lines.push(content);
        }
    }

    let chat_area = Paragraph::new(chat_lines)
        .block(Block::default().padding(Padding::new(2, 2, 0, 0))); 
        
    frame.render_widget(chat_area, chat_layout[0]);

    // --- INPUT BAR ---
    let input_border_color = if state.input.is_empty() { Color::DarkGray } else { Color::White };
    
    let input = Paragraph::new(state.input.as_str())
        .style(Style::default().fg(Color::White))
        .block(Block::default()
            .borders(Borders::TOP) 
            .border_style(Style::default().fg(input_border_color))
            .title(Span::styled(" Write a message ", Style::default().fg(Color::DarkGray))));
            
    frame.render_widget(input, chat_layout[1]);
}