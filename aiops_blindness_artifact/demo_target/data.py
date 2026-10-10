"""Fake data for the AI Conference demo site."""

SPEAKERS = [
    {"id": "s1", "name": "Dr. Elena Vasquez", "role": "Chief AI Scientist, NeuroTech", "bio": "Pioneer in neural-symbolic reasoning. Previously led research at MIT CSAIL.", "avatar": "👩‍🔬", "track": "Research"},
    {"id": "s2", "name": "Marcus Chen", "role": "VP Engineering, Scale AI", "bio": "Building large-scale ML infrastructure. Ex-Google Brain.", "avatar": "👨‍💻", "track": "Engineering"},
    {"id": "s3", "name": "Dr. Priya Sharma", "role": "Head of Ethics, AI Institute", "bio": "Author of 'Fair Models in Practice'. Focus on accountability and bias.", "avatar": "👩‍⚖️", "track": "Ethics"},
    {"id": "s4", "name": "James Okonkwo", "role": "Founder, AutoML Labs", "bio": "AutoML and NAS expert. Y Combinator alumni.", "avatar": "🧑‍🏫", "track": "Engineering"},
    {"id": "s5", "name": "Dr. Yuki Tanaka", "role": "Professor, Tokyo University", "bio": "Multimodal models and vision-language. ICML area chair.", "avatar": "👨‍🔬", "track": "Research"},
    {"id": "s6", "name": "Sarah Mitchell", "role": "Director of Product, OpenAI", "bio": "Shaping ChatGPT and API products. 15 years in AI product.", "avatar": "👩‍💼", "track": "Product"},
]

SESSIONS = [
    {"id": "ses1", "title": "Keynote: The Next Decade of General AI", "speaker_id": "s1", "room": "Main Hall", "day": 1, "start": "09:00", "end": "10:00", "track": "Research", "description": "A vision of where general-purpose AI is headed and what it means for industry and society."},
    {"id": "ses2", "title": "Scaling ML Pipelines to Billions of Examples", "speaker_id": "s2", "room": "Room A", "day": 1, "start": "10:30", "end": "11:30", "track": "Engineering", "description": "Practical patterns for training and serving models at massive scale."},
    {"id": "ses3", "title": "Fairness Audits: From Theory to Production", "speaker_id": "s3", "room": "Room B", "day": 1, "start": "10:30", "end": "11:30", "track": "Ethics", "description": "How to design and run fairness audits that stakeholders actually use."},
    {"id": "ses4", "title": "AutoML for Resource-Constrained Teams", "speaker_id": "s4", "room": "Room A", "day": 1, "start": "14:00", "end": "15:00", "track": "Engineering", "description": "Getting production-quality models without large ML teams."},
    {"id": "ses5", "title": "Vision-Language Models: Beyond Image Captioning", "speaker_id": "s5", "room": "Main Hall", "day": 1, "start": "14:00", "end": "15:00", "track": "Research", "description": "Latest advances in unified vision-language understanding and generation."},
    {"id": "ses6", "title": "Building AI Products Users Trust", "speaker_id": "s6", "room": "Room B", "day": 1, "start": "15:30", "end": "16:30", "track": "Product", "description": "Product and UX strategies for transparent, trustworthy AI interfaces."},
    {"id": "ses7", "title": "Panel: Regulation and Open Source", "speaker_id": "s3", "room": "Main Hall", "day": 2, "start": "09:00", "end": "10:00", "track": "Ethics", "description": "How new regulations interact with open-source AI and what to expect."},
    {"id": "ses8", "title": "Efficient Inference at the Edge", "speaker_id": "s2", "room": "Room A", "day": 2, "start": "10:30", "end": "11:30", "track": "Engineering", "description": "Deploying low-latency models on devices and edge servers."},
    {"id": "ses9", "title": "Neural Architecture Search in 2025", "speaker_id": "s4", "room": "Room B", "day": 2, "start": "10:30", "end": "11:30", "track": "Engineering", "description": "State of the art in NAS and what comes next."},
    {"id": "ses10", "title": "Closing: From Research to Reality", "speaker_id": "s1", "room": "Main Hall", "day": 2, "start": "16:00", "end": "17:00", "track": "Research", "description": "Bridging the gap between cutting-edge research and real-world deployment."},
]

AGENDA_DAYS = [
    {"day": 1, "date": "March 15, 2026", "label": "Day 1"},
    {"day": 2, "date": "March 16, 2026", "label": "Day 2"},
]

TICKET_TYPES = [
    {"id": "early", "name": "Early Bird", "price": 299, "desc": "Full access, limited availability"},
    {"id": "standard", "name": "Standard", "price": 449, "desc": "Full access to all sessions and networking"},
    {"id": "vip", "name": "VIP", "price": 799, "desc": "Front-row seating, speaker dinner, swag bag"},
]

# Mock users for login (password is "demo" for all)
MOCK_USERS = {
    "demo@example.com": {"name": "Demo User", "password": "demo"},
    "alice@example.com": {"name": "Alice Demo", "password": "demo"},
    "bob@example.com": {"name": "Bob Demo", "password": "demo"},
}

def get_speaker(speaker_id):
    return next((s for s in SPEAKERS if s["id"] == speaker_id), None)

def get_sessions_for_speaker(speaker_id):
    return [s for s in SESSIONS if s["speaker_id"] == speaker_id]

def get_sessions_by_day(day):
    return [s for s in SESSIONS if s["day"] == day]

def search_sessions(query):
    if not query or not query.strip():
        return SESSIONS
    q = query.strip().lower()
    return [
        s for s in SESSIONS
        if q in s["title"].lower()
        or q in s["track"].lower()
        or q in (get_speaker(s["speaker_id"]) or {}).get("name", "").lower()
        or q in s.get("description", "").lower()
    ]
