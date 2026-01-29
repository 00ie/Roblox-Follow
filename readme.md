# Roblox Follow Bot

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Release](https://img.shields.io/badge/Release-1.0.0-brightgreen.svg)
![Roblox](https://img.shields.io/badge/Roblox-API-red.svg)

## Overview

Roblox Follow Bot is a Python-based automation tool that performs follow requests on a target Roblox user using multiple accounts.  
The project focuses on HTTP request automation with basic concurrency, optional proxy usage, and a graphical interface.

This tool operates by emulating browser-like requests and relies on the current behavior of Roblox endpoints. It does **not** implement verified cryptographic authentication or advanced anti-detection techniques.

---

## Features

- **Mass Following**  
  Send follow requests to a target user using multiple Roblox account cookies.

- **Multi-Threaded Execution**  
  Concurrent processing using Python threads (configurable from 1 to 20).

- **Cookie-Based Sessions**  
  Uses `.ROBLOSECURITY` cookies to authenticate requests.

- **Optional Proxy Support**  
  Random proxy selection per request (no proxy health persistence).

- **Retry Mechanism**  
  Up to 3 retry attempts per cookie with incremental delays.

- **CSRF Token Handling**  
  Automatically retrieves and applies `x-csrf-token` headers.

- **Real-Time Statistics**  
  Tracks successes, failures, and execution rate.

- **GUI and CLI Modes**  
  Includes a CustomTkinter-based interface and a basic CLI flow.

- **Bilingual Interface**  
  English and Portuguese UI support.

- **Auto File Setup**  
  Automatically creates required folders and files on first run.

---

## Requirements

- Python 3.8 or higher
- Roblox account cookies (`.ROBLOSECURITY`)
- Optional: HTTP or HTTPS proxies

### Main Dependencies
- `curl_cffi`
- `cryptography`
- `customtkinter`
- `colorama`
- `requests` (GUI proxy test only)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or download the repository:
```bash
git clone https://github.com/yourusername/roblox-follow-bot.git
cd roblox-follow-bot
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

The application will automatically create the necessary folders on first run:
- `input/` - For cookies and proxies
- `output/` - For results
- `logs/` - For execution logs

---

## File Structure

```
roblox-follow-bot/
├── main.py                 # Main application (GUI + core)
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── input/
│   ├── cookies.txt        # Roblox cookies (.ROBLOSECURITY)
│   └── proxies.txt        # Optional proxies
├── output/
│   └── results.txt        # Execution output (reserved)
└── logs/
    └── summary.txt        # Execution summary (reserved)
```

---

## Usage

### Adding Cookies

1. Open `input/cookies.txt`
2. Add one `.ROBLOSECURITY` cookie per line
3. Cookies must be valid Roblox session cookies

Example cookie format:
```
_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_...
```

### Adding Proxies (Optional)

1. Open `input/proxies.txt`
2. Add one proxy per line  

Supported formats:
```
http://host:port
https://host:port
http://user:pass@host:port
```

---

## Running the Bot

### GUI Mode

```bash
python main.py
```

1. Enter the target Roblox User ID
2. Select the number of threads
3. (Optional) Check cookies and proxies
4. Click START BOT
5. Monitor logs in real time

### CLI Mode

The core logic can also be executed via terminal prompts if the GUI is bypassed.

---

## How It Works

### Authentication Flow

1. Loads cookies and proxies from input files
2. Distributes cookies across worker threads
3. For each request:
   - Creates a new HTTP session
   - Applies browser-like headers
   - Sets authentication cookie
   - Retrieves CSRF token
   - Sends follow request to Roblox API
4. Retries failed attempts up to 3 times
5. Updates shared performance metrics

### Authentication and Headers

- Uses `.ROBLOSECURITY` cookies for session authentication
- Automatically retrieves `x-csrf-token`
- Generates a locally signed `x-bound-auth-token` header for format compatibility only

**Note**: The token is not cryptographically verified by Roblox and should not be considered secure authentication.

### Browser Emulation

- Random User-Agent rotation (Chrome / Safari)
- Static browser-like headers
- TLS impersonation via `curl_cffi`


---

## Performance Metrics

Displayed during execution:

- **Success Count** – Successful follow responses
- **Failure Count** – Failed attempts (counted per retry)
- **Total Attempts** – Successes + failures
- **Success Rate** – Percentage of successful attempts
- **Rate/Min** – Successful follows per minute

---

## Error Handling

### Common Outcomes

**Unauthorized / Invalid Cookie**  
Cookie expired or invalid. Obtain a fresh cookie.

**CSRF Token Retrieval Failed**  
Session could not obtain a CSRF token. Check network or cookie validity.

**Rate Limited (429)**  
Too many requests in a short period. Reduce threads or add delays.

**Captcha Required**  
Roblox detected automated behavior. Use proxies or reduce frequency.

**Proxy Connection Failed**  
Proxy is unreachable or blocked. Test proxies before use.

---

## Security Notes

**Important Security Information**:

- `.ROBLOSECURITY` cookies provide full account access
- Never share or commit cookies to public repositories
- Use throwaway or test accounts only
- Enable 2FA on all Roblox accounts
- Store cookies securely

---

## Legal Disclaimer

This project is provided for **educational and experimental purposes only**.

Users are responsible for:
- Complying with Roblox Terms of Service
- Understanding the risks of automation
- Any consequences resulting from use of this tool

**Automated actions may result in account suspension or termination. Use at your own risk.**

---

## Project Status

**Experimental**

- Highly dependent on current Roblox backend behavior
- Not guaranteed to remain functional
- Updates may break functionality

---

## Troubleshooting

### Bot not starting
- Verify Python version: `python --version` (must be 3.8+)
- Check all dependencies are installed: `pip install -r requirements.txt`
- Ensure `input/cookies.txt` exists and contains valid cookies

### No proxies working
- Verify proxy format: `http://host:port`
- Test proxies manually
- Some proxies may be blocked by Roblox
- Try different proxy providers

### High failure rate
- Cookies may be expired - refresh them
- Reduce thread count to avoid rate limits
- Add more proxies to distribute load
- Increase delay between requests

---

## Changelog

### Version 1.0.0
- Initial release
- Multi-threaded follow bot
- Cookie management system
- Proxy rotation support
- CustomTkinter GUI
- Bilingual interface (EN/PT)
- Real-time statistics tracking
- Smart retry logic with backoff
- CSRF token automation
- Auto-setup on first run

---

## Support

For support, questions, or issues:

- **GitHub**: [00ie](https://github.com/00ie)
- **Telegram**: [@feicoes](https://t.me/feicoes)
- **Discord**: tlwm
- **Community Server**: [https://discord.gg/2asv4rEhGh](https://discord.gg/2asv4rEhGh)

---

## Credits

**Developed by Gon**

---

## License

This project is licensed under the MIT License.

---

If you find this tool useful, please consider starring the repository.