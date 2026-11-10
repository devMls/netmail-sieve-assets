//! Source ranges are aligned to the reference AST and reference lexer, not
//! reparsed by a second Sieve grammar. All untouched bytes remain unchanged.
use mailrs_sieve_core::{parse_script, tokenize_spanned, Command, SpannedToken, Token};
use serde::Serialize;

pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub start: usize,
    pub end: usize,
    pub children: Vec<Node>,
}

pub struct Document {
    pub commands: Vec<Command>,
    pub nodes: Vec<Node>,
}

pub fn parse(source: &str) -> Result<Document, String> {
    if source.len() > MAX_SCRIPT_BYTES || source.contains('\0') {
        return Err("InputLimit: script exceeds 256 KiB or contains NUL".into());
    }
    let tokens = tokenize_spanned(source).map_err(|e| format!("SyntaxError: {e}"))?;
    // Bound recursive reference parsing before entering the parser. Count both
    // blocks and nested test expressions (not chains have no parentheses).
    let mut depth = 0usize;
    let mut not_count = 0usize;
    for t in &tokens {
        match &t.token {
            Token::LBrace | Token::LParen => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err("InputLimit: nesting exceeds 64".into());
                }
            }
            Token::RBrace | Token::RParen => depth = depth.saturating_sub(1),
            Token::Identifier(name) if name == "not" => {
                not_count += 1;
                if not_count > MAX_DEPTH {
                    return Err("InputLimit: too many nested not tests".into());
                }
            }
            _ => {
                not_count = 0;
            }
        }
    }
    let commands = parse_script(source).map_err(|e| format!("SyntaxError: {e}"))?;
    let mut cursor = 0;
    let nodes = align(&commands, &tokens, &mut cursor)?;
    if cursor != tokens.len() {
        return Err("SyntaxError: unconsumed source tokens".into());
    }
    check_structure(&commands, true)?;
    Ok(Document { commands, nodes })
}

fn align(
    commands: &[Command],
    tokens: &[SpannedToken],
    cursor: &mut usize,
) -> Result<Vec<Node>, String> {
    let mut nodes = Vec::new();
    for command in commands {
        let first = tokens
            .get(*cursor)
            .ok_or("SyntaxError: missing command token")?;
        if first.token != Token::Identifier(command.name.clone()) {
            return Err("SyntaxError: reference AST/source alignment failed".into());
        }
        let start = first.start;
        *cursor += 1;
        while let Some(t) = tokens.get(*cursor) {
            if matches!(t.token, Token::Semicolon | Token::LBrace) {
                break;
            }
            *cursor += 1;
        }
        let terminal = tokens
            .get(*cursor)
            .ok_or("SyntaxError: missing command terminator")?;
        let (children, end) = match terminal.token {
            Token::Semicolon if command.block.is_empty() => {
                *cursor += 1;
                (Vec::new(), terminal.end)
            }
            Token::LBrace => {
                *cursor += 1;
                let children = align(&command.block, tokens, cursor)?;
                let closing = tokens
                    .get(*cursor)
                    .ok_or("SyntaxError: missing block terminator")?;
                if closing.token != Token::RBrace {
                    return Err("SyntaxError: block alignment failed".into());
                }
                *cursor += 1;
                (children, closing.end)
            }
            _ => return Err("SyntaxError: unsupported AST/source shape".into()),
        };
        nodes.push(Node {
            start,
            end,
            children,
        });
    }
    Ok(nodes)
}

fn check_structure(commands: &[Command], top: bool) -> Result<(), String> {
    let mut body_started = false;
    let mut branch_open = false;
    for command in commands {
        match command.name.as_str() {
            "require" if !top || body_started || !command.block.is_empty() => {
                return Err("SyntaxError: require must precede all executable commands".into())
            }
            "require" => {}
            "elsif" | "else" if !branch_open => return Err("SyntaxError: orphan elsif/else".into()),
            "else" => {
                branch_open = false;
                body_started = true;
            }
            "if" | "elsif" => {
                branch_open = true;
                body_started = true;
            }
            _ => {
                branch_open = false;
                body_started = true;
            }
        }
        check_structure(&command.block, false)?;
    }
    Ok(())
}
