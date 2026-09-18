# Nurses & Midwives Hub — V6

A local-development build of an international nursing and midwifery learning, careers, abroad-information, document-evaluation and premium community platform.

## V6 user experience

### Public website
- Clean landing page
- Generated healthcare imagery and Hub logo
- Student vs Graduate / Professional entry
- 7-day full Premium trial explanation
- GHS 50/month Premium
- GHS 450 Document Evaluation
- Study, N&MC Practice, AI Tutor, Daily Tutorial, Nutrition, Jobs, Abroad, News, Community, Stories and Enquiries discovery

### Student profile
Students select their actual university/training college from the N&MC directory snapshot stored in `data/institutions.json`. Graduate / Professional profiles do not require an institution.

Current N&MC accreditation/licensing information should always be checked against the N&MC's live site before treating a directory item as current.

### Study Hub
- Nursing, midwifery, community/public-health, professional practice and nutrition tracks
- Module -> lesson -> notes flow
- Previous / Next lessons
- Progress saving
- AI Tutor hook
- Daily AI tutorial hook
- Original Hub N&MC-style preparation questions
- Theory prompts and performance analytics

The Hub does not claim to reproduce official N&MC exam papers.

### Premium access
A new account starts a server-side 7-day trial:
- Days/hours/minutes/seconds update automatically
- Full Premium access during trial
- Study, practice, AI, Nutrition, careers, abroad and community are Premium
- After trial expiry, Premium routes are locked until a successful subscription

### Payment
Commercial prices:
- Premium: GHS 50/month
- Document Evaluation: GHS 450

Paystack is prepared for server-side initialization, verification and webhook signature checking.

Set in `.env`:
- `PAYSTACK_PUBLIC_KEY`
- `PAYSTACK_SECRET_KEY`
- `PAYSTACK_SUBSCRIPTION_PLAN_CODE`

Never place a Paystack secret in frontend code or commit it to source control.

### Document Evaluation
Two routes:
- Job Abroad
- School Abroad

The service collects applicant details and documents, creates a submission reference, and stores the review status. Administrators can inspect submissions and message the member as **Hub Admin**.

The production version should use private managed object storage plus antivirus/malware scanning and a stricter retention policy.

### Jobs
Users can:
- Filter by country
- Read the full job details inside the Hub
- Save a job
- Track an application
- Use the explicit official application button when ready

Jobs hide the application URL from public content APIs until the user opens the application action.

Automatic opportunity refresh is supported through configured official RSS/JSON feeds in `OPPORTUNITY_FEEDS_JSON`.

Because there is no universal official feed for every job board, the Hub does not invent or scrape arbitrary sites.

### Abroad
The interface is explicitly labelled **Abroad** and separates:
- Study Abroad
- Work Abroad

Country pathway details are read inside the Hub. Explicit authority/application buttons can open the official source.

A curated study-option directory is included in `data/study-options.json`. It contains official university programme/admissions entry points. The Hub does not claim that every listed institution currently offers a specific nursing programme at every degree level; users are told to verify the current official programme finder before applying.

### News
News is intended to remain readable inside the Hub:
- Internal article body
- Source/date attribution
- Likes
- Comments
- Official-source button

Server-side news refresh pulls public-source information where available and creates Hub-authored summaries rather than copying full external articles.

### Community
Premium/trial members can use:
- Public community room
- Friend suggestions
- Friend requests
- 1-to-1 messaging
- Groups
- Status posts
- Image/audio/video attachments (size limited in server config)
- Notifications
- Browser notifications
- Notification sound
- Message reporting
- Hub Admin messaging

For real scale, the WebSocket and persistence layer should move to managed infrastructure.

## AI configuration

AI is optional in local development.

Set:
```env
OPENAI_API_KEY=...
OPENAI_MODEL=...
OPENAI_BASE_URL=https://api.openai.com/v1/responses
```

Without an API key/model, the Hub uses a safe fallback tutor/tutorial response so the interface remains usable.

Never place the AI API key in browser JavaScript.

## Email / password reset

Password reset works locally with a development reset URL.

For production, configure:
```env
RESEND_API_KEY=...
RESEND_FROM_EMAIL=Hub <no-reply@yourdomain.example>
```

Use a production email provider, verified domain, abuse controls and rate limits.

## Run locally

```powershell
npm.cmd install
Copy-Item .env.example .env
node server.js
```

Open:
`http://localhost:3000`

Health check:
`http://localhost:3000/api/health`

## Admin

Open:
`http://localhost:3000/admin.html`

Use a strong administrator password and change all example credentials before deployment.

## Security and production readiness

V6 includes:
- `helmet`
- rate limiting
- CSRF checks
- HttpOnly session cookies
- password hashing with `scrypt`
- server-side payment verification
- webhook verification
- upload validation
- filename sanitization
- private media authorization
- message/report controls
- admin authorization

This is a robust application scaffold, not a security-audited production service.

### Before public launch
Replace local JSON persistence with:
- PostgreSQL
- Redis / managed pub-sub
- object storage
- background job queue
- structured logs
- centralized monitoring
- backups
- MFA for administrators
- secret manager
- malware scanning
- stricter CSP
- account lockout / anti-abuse controls
- privacy policy / terms / data-retention controls
- professional legal and compliance review

Do not attempt to serve 100,000+ concurrent users from this JSON-file architecture. The UI/API boundaries are intentionally structured so persistence and realtime infrastructure can later be migrated to managed scalable services.

## Source policy

Use official regulator, government, university and employer pages for authoritative requirements. News summaries should be newly written, attributed and kept within fair-use/copyright limits.

Examples of authoritative starting points:
- Ghana Nursing and Midwifery Council
- UK Nursing and Midwifery Council
- Nursing Council of New Zealand
- NNAS Canada
- Ahpra / NMBA Australia
- University admissions sites
- Government and major public-health organizations
