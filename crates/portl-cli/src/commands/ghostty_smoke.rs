use std::process::ExitCode;

use anyhow::Result;

#[cfg(feature = "ghostty-vt")]
pub fn run() -> Result<ExitCode> {
    use libghostty_vt::{Terminal, TerminalOptions};

    let mut terminal = Terminal::new(TerminalOptions {
        cols: 80,
        rows: 24,
        max_scrollback: 128,
    })?;
    terminal.vt_write(b"Hello, \x1b[1;32mghostty\x1b[0m!\r\n");

    let cols = terminal.cols()?;
    let rows = terminal.rows()?;
    let cursor_x = terminal.cursor_x()?;
    let cursor_y = terminal.cursor_y()?;

    println!("ghostty-vt smoke ok cols={cols} rows={rows} cursor_x={cursor_x} cursor_y={cursor_y}");
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "ghostty-vt"))]
pub fn run() -> Result<ExitCode> {
    anyhow::bail!("ghostty-vt support is not built into this portl binary")
}
