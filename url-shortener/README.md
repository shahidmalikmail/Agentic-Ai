# URL Shortener

A simple, local URL shortener built with Flask and SQLite.

## Features

- Shorten long URLs into short codes
- Redirect short URLs to their original destination
- Copy the generated short URL with one click
- URL validation with error messages
- View all shortened URLs with click counts

## Setup (Windows)

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Project structure

```text
url-shortener/
├── app.py
├── requirements.txt
├── database.db
├── templates/
│   ├── index.html
│   └── urls.html
├── static/
│   ├── style.css
│   └── script.js
└── README.md
```

## Notes

- `database.db` is created automatically on first run if it doesn't exist.
- Short codes are 6-character random alphanumeric strings, checked for uniqueness before saving.
