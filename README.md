# Web Fuzzer - Web Vulnerability Scanner

## Overview

**Web Fuzzer** is a powerful web vulnerability scanner designed to identify common security issues on websites. It performs checks on headers, technologies used, potential vulnerabilities, and open ports, providing insights to help enhance web application security. Whether you are a developer, security researcher, or system administrator, this tool can assist in identifying and mitigating web security risks.

## Features

- **Website Header Scanning**: Analyzes response headers for common security flaws.
- **Technology Detection**: Identifies technologies used by a website, such as CMS, frameworks, and servers.
- **Vulnerability Detection**: Scans for vulnerabilities like Cross-Site Scripting (XSS), SQL Injection, Remote File Inclusion (RFI), Local File Inclusion (LFI), and more.
- **Port Scanning**: Detects open ports to identify potential attack vectors.
- **Security Recommendations**: Provides actionable security advice based on scan results.

## Installation

To get started with Web Fuzzer, follow these steps:

### Prerequisites

- Python 3.x
- Flask
- Flask-WTF
- Nmap
- Requests
- BeautifulSoup4

### Clone the Repository

```bash
https://github.com/noorulhassan1408/Lethality.git
cd Lethality
```

### Install Dependencies

Create a virtual environment and install required dependencies:

```bash
python3 -m venv venv
source venv/bin/activate   # For Linux/macOS
venv\Scripts\activate      # For Windows
pip install -r requirements.txt
```

### Install Nmap

**Web Fuzzer** uses **Nmap** for port scanning. Make sure Nmap is installed:

- **Linux**: `sudo apt install nmap`
- **Windows**: Download from [Nmap Official Site](https://nmap.org/download.html)
- **Mac**: `brew install nmap`

### Run the Application

To run the app locally, use the following commands:

```bash
python app.py
```

The app will be available at `http://127.0.0.1:5000/`.

## Usage

1. **Home**: Input the URL of the website you want to scan and click "Scan" to begin the analysis.
2. **Scan Results**: View detailed results across multiple tabs:
   - **Headers**: Lists the HTTP headers returned by the server.
   - **Technology**: Displays technologies detected from the website's headers and meta tags.
   - **Vulnerabilities**: Lists detected vulnerabilities, such as XSS, SQL Injection, etc.
   - **Open Ports**: Displays open ports discovered during the Nmap scan.
3. **Security Advice**: Based on the scan results, the app provides recommended actions to improve the site's security.
4. **About**: Learn more about the Web Fuzzer project, including technologies used.

## File Structure

```
.
├── app.py              # Main application file
├── forms.py            # Form validation and handling
├── requirements.txt    # Required dependencies list
├── scanner/            # Contains scanning logic
│   ├── __init__.py     # Package initializer
│   └── scanner.py      # Web scanning logic (headers, vulnerabilities, ports, etc.)
├── static/             # Static files (CSS)
│   └── styles.css      # Styles for the web interface
└── templates/          # HTML templates
    ├── about.html      # About page
    ├── advice.html     # Security advice page
    ├── base.html       # Base template
    ├── index.html      # Homepage template
    └── results.html    # Results page template
```

## Security Recommendations

After scanning a website, **Web Fuzzer** provides a detailed list of security best practices, such as:

- **Input Validation**: Always sanitize and validate user inputs to prevent XSS, SQL Injection, and other attacks.
- **HTTPS**: Use HTTPS to ensure data encryption.
- **Content Security Policy**: Implement CSP headers to mitigate XSS attacks.
- **Regular Updates**: Keep your software and dependencies up-to-date.
- **Disable Unused Ports**: Close unnecessary open ports.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request. Here's how you can contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

For any questions or feedback, feel free to open an issue or contact the maintainer. Happy scanning! 🚀
