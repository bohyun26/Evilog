# AI Conference Demo Website

A small, self-contained multi-page demo site for an AI conference. Built with Flask and in-memory fake data. No database or external services required.

## Features (mock)

- **Home** — hero, featured speakers, upcoming sessions
- **Agenda** — day-by-day schedule (Day 1 / Day 2)
- **Sessions** — list with search by title, track, or speaker
- **Speakers** — grid of speakers and speaker detail pages
- **Buy tickets** — choose tier, enter name/email, see confirmation (no payment)
- **Log in / Log out** — mock auth (credentials below)
- **Profile** — simple profile page when logged in

## Run locally

```bash
cd demo_target
pip install -r requirements.txt
python app.py
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080).

## Demo login

Use any of:

- **demo@example.com** / **demo**
- **alice@example.com** / **demo**
- **bob@example.com** / **demo**

## Project layout

```
demo_target/
├── app.py           # Flask app and routes
├── data.py          # Fake data (speakers, sessions, agenda, tickets, users)
├── requirements.txt
├── README.md
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── base.html
    ├── index.html
    ├── agenda.html
    ├── sessions.html
    ├── session_detail.html
    ├── speakers.html
    ├── speaker_detail.html
    ├── tickets.html
    ├── tickets_confirm.html
    ├── login.html
    ├── profile.html
    └── 404.html
```

All data is defined in `data.py` and is fictional.
