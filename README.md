# Vulnerable Web App

## Overview
This project is a purposefully vulnerable web application. It mimics a simple social networking platform where users can post messages, view profiles, and update settings.

**Warning:** This application contains intentional security flaws (SQL Injection, XSS, etc.) and is intended strictly for educational and testing purposes. Do not run this application in a production environment or on a public server.

## Technology Stack
The application is built using the following technologies:
- **Backend:** Python 3, Flask
- **Database:** SQLite (In-Memory)
- **Frontend:** HTML5, CSS3, Jinja2 Templates

## Project Structure
```
vulnerable_app/
├── app.py              # Main application logic and routes
├── requirements.txt    # Python dependencies
├── static/
│   └── style.css       # Static assets and styling
└── templates/          # HTML Templates
    ├── base.html       # Base layout
    ├── index.html      # Home/Feed page
    ├── login.html      # Authentication page
    ├── user.html       # User profile page
    ├── settings.html   # User settings page
    └── results.html    # Search results page
```

## Setup and Installation

### Prerequisites
- Python 3.x
- `pip` (Python Package Manager)

### Installation
1. Navigate to the project directory:
   ```bash
   cd vulnerable_app
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application
To start the web server, run:

```bash
python app.py
```

The application will be accessible at `http://127.0.0.1:5000/`.

## Features
- **User Authentication:** Users can login (default credentials provided in `app.py` for testing).
- **Posting System:** Users can create public or private posts.
- **Comments:** Users can comment on posts.
- **Search:** A search feature to find posts or users.
- **Profile Management:** Users can update their display name, description, and password.

## Intended Vulnerabilities
This application is designed to demonstrate common web security vulnerabilities, including but not limited to:
- **SQL Injection (SQLi):** Vulnerable queries in login, search, and profile update modules.
- **Cross-Site Scripting (XSS):** Reflected and stored XSS vulnerabilities in search results and comments.
- **Broken Access Control:** Issues with session management and post privacy.

## Disclaimer
This software is provided for educational use only. The authors are not responsible for any misuse of this code.
