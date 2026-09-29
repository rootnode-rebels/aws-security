```
SHIP FAST, SHIP SAFE
```



### VIBE CODING SECURITY RISKS 

**10 Security Mistkes AI Coding Assistnts Mke Silently  Wht Every "Vibe Coder" Ships Without Knowing, nd How to Fix It Before It Bites You.** 

AI pir-progrmmers write code tht runs — not code tht's sfe. They optimize for "it works," not "it cn't be bused." These re the 10 gps tht show up over nd over in AI-generted pps, with the exct fix for ech. 

**Dileep Kumr** Instgrm: @dileep.idev 

#### **SECURITY BY LAYER** 

Sme 10 risks, mpped to where they ctully live in your stck — so you know exctly which file to go check. 

**FRO N TE N D** Rect / TypeScript / Next.js 

###### **Secrets in client bundle** 

**BAD** API key used directly in  component / `fetch()` cll **GOOD** cll your own bckend route; keep the rel key server-side only 

###### **Trusting client-side vlidtion** 

**BAD** only checking form fields with JS before submit **GOOD** tret frontend vlidtion s UX only — revlidte on the server 

###### **Unsnitized rendering XSS** 

**BAD** `dangerouslySetInnerHTML` on user content **GOOD** render s text by defult; snitize with  librry if HTML is required 

###### **Tokens in loclStorge** 

**BAD** storing JWTs in loclStorge, redble by ny injected script **GOOD** prefer httpOnly, secure cookies for session tokens 

**BACKE N D** FstAPI / Node / Python 

###### **No uth/ownership check per route** 

**BAD** ny logged-in user cn hit ny user's `/orders/:id` **GOOD** check `record.owner_id == current_user.id` on every red/write 

###### **Debug mode / stck trces exposed** 

**BAD** `DEBUG=True` , rw exceptions returned s JSON 

**GOOD** generic error responses in prod; log the rel trce server-side only 

###### **No rte limiting on uth routes** 

**BAD** login / OTP endpoints ccept unlimited requests **GOOD** dd per-IP nd per-ccount throttling + lockout 

###### **CORS wide open** 

**BAD** `Access-Control-Allow-Origin: *` to "mke it work" 

**GOOD** llow-list your ctul frontend origin(s) only 

**DATA BA SE** PostgreSQL / MongoDB 

###### **Rw string-built queries** 

**BAD** `f"SELECT * WHERE email='{email}'"` **GOOD** prmeterized queries or n ORM (SQLAlchemy, Prism) — lwys 

###### **Plin-text or wekly hshed psswords** 

**BAD** storing psswords s MD5/SHA1, or plin text **GOOD** bcrypt / Argon2id with  unique per-user slt 

###### **DB user hs full dmin rights** 

**BAD** pp connects s  superuser / root DB ccount **GOOD** lest-privilege DB user — only the grnts the pp ctully needs 

###### **No bckups / no migrtion review** 

**BAD** AI-generted migrtion runs stright ginst prod dt **GOOD** utomted bckups + review destructive migrtions before pplying 

A request usully breks becuse of one lyer — but gets exploited becuse no other lyer ctches it. Vlidte on the frontend for UX, recheck on the bckend for security, nd constrin the dtbse so even  bckend bug cn't do full dmge. 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
02 / 08
```

###### **`V01` HARDCODED SECRETS IN GENERATED CODE** 

AI ssistnts frequently write API keys, DB psswords, or JWT secrets stright into the source file "to keep the demo simple" — nd it ships tht wy. 

###### **W HY I T HAPPE NS** 

Prompt sys "connect to Postgres"  AI writes the pssword inline insted of reding n env vr 

Smple `.env.example` gets committed with rel vlues still in it 

Frontend code clls  pid API directly, exposing the key in browser dev tools 

###### **SC E NARI O** 

A solo builder ships  SS MVP built entirely by prompting. Someone opens the public GitHub repo, greps for `"sk-"` or `"AIza"` , nd finds  live API key still ctive  week fter lunch. 

###### **F I X** 

Move every secret to environment vribles /  secrets mnger before first deploy. Add  precommit hook or GitHub secret-scnning to ctch keys before they're pushed. 

###### **`V02` NO INPUT VALIDATION ON THE HAPPY PATH** 

AI-generted endpoints hndle the cse where the user behves — not the cse where they don't. Vlidtion is usully missing unless you explicitly sk for it. 

###### **C OM M ON E X AM PLE S** 

Form fields ccept ny length, ny type, ny chrcters 

File uplod ccepts ny extension or size — no MIME check 

Numeric fields (price, quntity) ccept negtive numbers or strings 

###### **SC E NARI O** 

A "vibe coded" booking pp lets  user submit  negtive number of nights, nd the totl-price clcultion hppily returns  negtive bill — which the pyment gtewy then tries to refund. 

###### **F I X** 

Vlidte nd snitize every input server-side (type, rnge, length) even if the frontend lredy checks it. Never trust client-side vlidtion lone. 

###### **`V03` MISSING OWNERSHIP / AUTHORIZATION CHECKS** 

Ask n AI to "build  delete endpoint" nd it usully deletes by ID  without checking tht the requester ctully owns tht record. 

###### **C OM M ON E X AM PLE S** 

`DELETE /api/orders/:id` with no check tht `order.userId === req.user.id` 

Admin-only routes rechble by ny logged-in user becuse the role check ws never dded IDs re sequentil integers, mking other users' records trivil to guess 

###### **SC E NARI O** 

A vibe-coded dshbord lets User A chnge the ID in the URL from their own invoice to 

`/invoice/451` nd view — or cncel — someone else's order. 

###### **F I X** 

Add n explicit ownership/role check in every route tht reds or muttes  record, not just in the ones the AI hppened to dd it to. 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
03 / 08
```

###### **`V04` DEBUG MODE & VERBOSE ERRORS LEFT ON** 

AI scffolds projects with debug flgs on by defult, becuse tht's wht mkes locl development esy — nd it's rrely turned off before deploy. 

###### **C OM M ON E X AM PLE S** 

###### `DEBUG=True` / `app.debug = True` shipped to production 

Full stck trces (file pths, librry versions, env vrs) shown directly to the end user on error CORS set to `*` "to stop fighting the browser" nd never revisited 

###### **SC E NARI O** 

A crsh on  live vibe-coded pp returns  full Python trcebck in the browser, reveling the internl file structure nd the dtbse connection string. 

###### **F I X** 

Use seprte dev/prod configs. Before shipping, explicitly turn off debug mode, restrict CORS to rel origins, nd return generic error messges to users. 

###### **`V05` QUERIES BUILT WITH STRING CONCATENATION** 

When prompted quickly, AI models sometimes build SQL or NoSQL queries by conctenting user input directly into the query string insted of using prmeterized queries. 

###### **C OM M ON E X AM PLE S** 

- `"SELECT * FROM users WHERE email = '" + email + "'"` 

- MongoDB filters built from rw `req.body` without type-checking, llowing opertor injection like `{"$ne": null}` 

###### **SC E NARI O** 

A vibe-coded login form built quickly from  prompt is vulnerble to  clssic `' OR '1'='1` injection becuse the query ws never prmeterized. 

###### **F I X** 

Alwys use n ORM or prmeterized/prepred sttements. If you pste AI-generted DB code, specificlly check every query for rw string conctention before trusting it. 

###### **`V06` NO RATE LIMITING OR BRUTE-FORCE PROTECTION** 

Throttling isn't something AI dds unless sked — login, OTP, nd pssword-reset endpoints usully ship wide open to utomted buse. 

###### **C OM M ON E X AM PLE S** 

Login endpoint ccepts unlimited ttempts per second 

OTP / pssword-reset endpoint hs no cooldown or ttempt cp 

Public API hs no per-user or per-IP request quot, inviting scrping or cost-buse 

###### **SC E NARI O** 

A vibe-coded OTP login flow lets  script try ll 10,000 four-digit codes in under  minute becuse nothing throttles the ttempts. 

###### **F I X** 

Add rte limiting (per IP nd per ccount) on uth-sensitive routes, plus exponentil lockout fter repeted filures. 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
04 / 08
```

###### **`V07` OUTDATED OR UNVERIFIED PACKAGE SUGGESTIONS** 

AI trining dt lgs behind — it cn suggest  pckge version with known CVEs, or  pckge nme tht's been typosqutted, without flgging either. 

###### **C OM M ON E X AM PLE S** 

Instlling n old, pinned version of  librry tht hs  public unptched vulnerbility 

- AI hllucintes  plusible-sounding pckge nme tht doesn't exist — which n ttcker hs since registered nd filled with mlwre 

No lockfile, so builds pull in whtever the ltest (possibly compromised) version is 

###### **SC E NARI O** 

A developer instlls  pckge n AI ssistnt recommended by nme, without checking it on npm/PyPI first — the pckge turns out to be  typosqut of  populr librry. 

###### **F I X** 

Verify every AI-suggested pckge ctully exists nd is ctively mintined before instlling. Run  dependency/CVE scn nd commit  lockfile. 

###### **`V08` NO ERROR HANDLING / SILENT FAILURES** 

Quick AI-generted code often skips try/ctch entirely, or wrps things in  brod ctch tht hides rel filures — including security-relevnt ones. 

###### **C OM M ON E X AM PLE S** 

Pyment or uth clls with no try/ctch —  timeout crshes the whole process 

- A brod `catch (e) {}` silently swllows filed permission checks, letting the request continue s if it succeeded 

No fllbck stte defined, so  filed request leves the UI or DB in n inconsistent stte 

###### **SC E NARI O** 

A vibe-coded checkout flow's pymentconfirmtion cll fils silently; the order is mrked "pid" in the UI nywy becuse the error ws swllowed insted of hndled. 

###### **F I X** 

Hndle every externl cll explicitly (network, DB, pyment) nd fil closed — deny/rollbck by defult, never ssume success. 

###### **`V09` BLIND TRUST — SHIPPING WITHOUT A SECURITY READTHROUGH** 

The single biggest risk isn't ny one bug — it's psting AI output stright into production without  humn reding it for security, not just correctness. 

###### **C OM M ON E X AM PLE S** 

Copy-psting n entire uth flow from  cht response without checking token hndling 

- Accepting AI-suggested "quick fixes" for bugs tht ctully reintroduce  vulnerbility (e.g. disbling  check to "mke the error go wy") 

No code review step t ll before deploying to rel users 

###### **SC E NARI O** 

An AI ssistnt, sked to "fix this CORS error," suggests setting 

`Access-Control-Allow-Origin: *` —  builder in 

###### **F I X** 

Tret AI output like  junior dev's first drft: red every security-sensitive line (uth, pyments, file ccess, user input) before merging. 

 hurry ccepts it nd ships it, wide open. 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
05 / 08
```

###### **`V10` NO LOGGING OR MONITORING ON SENSITIVE ACTIONS** 

AI-generted MVPs re built to demo, not to be wtched — so there's usully no record of who did wht, which mens buse cn run for weeks unnoticed. 

###### **C OM M ON E X AM PLE S** 

Filed logins, permission denils, nd dmin ctions ren't logged nywhere 

No lerting on unusul spikes in trffic, signups, or filed pyments 

Logs, if they exist, hve no timestmps, IPs, or user IDs — useless for investigting n incident 

###### **SC E NARI O** 

A vibe-coded pp gets credentil-stuffed for three weeks stright. No lert ever fires, becuse nothing ws logging filed login ttempts in the first plce. 

###### **F I X** 

Log every uth event, permission filure, nd dmin ction with context (timestmp, IP, user ID. Wire t lest bsic lerting before you hve rel users. 

#### **1 MORE MISTAKES VIBE CODERS MAKE** 

Beyond the top 10  smller hbits tht show up constntly in AI-built pps nd quietly turn into rel incidents. 

###### **`01` No HTTPS enforced** 

App works over plin HTTP in prod, or mixes HTTP/HTTPS  login dt trvels unencrypted. 

**`02` Unprotected dmin routes** 

- `/admin` or `/internal` rechble by nyone who 

- finds the URL  no seprte uth gte. 

###### **`03` Public API docs / Swgger** 

- `/docs` or `/swagger` left open, hnding ttckers 

-  full mp of every endpoint. 

###### **`04` Client-only pywll checks** 

- "Premium" fetures gted only in the frontend 

- bypssed instntly from dev tools. 

###### **`05` Unrestricted file uplods** 

Any file type/size ccepted; uplods lnd in  public S/storge bucket with no ccess control. 

###### **`06` Sessions tht never expire** 

Login tokens issued with no expiry or refresh flow —  leked token works forever. 

###### **`07` Leftover test/demo ccounts** 

Seed dt like `admin/admin123` from locl testing shipped stright to production. 

###### **`08` Trusting client-sent prices** 

Checkout totl tken from the request body insted of reclculted server-side from the DB. 

###### **`09` Unverified webhooks** 

Incoming webhook clls Stripe, pyment, etc.) processed with no signture check — esy to spoof. 

###### **`10` One shred DB for everything** 

Dev, stging nd production reding/writing the sme dtbse nd secrets. 

###### **`11` Ungurded AI prompt inputs** 

Rw user text fed stright into n AI feture's system prompt — open to prompt injection. 

###### **`12` "AI lredy checked it" mindset** 

Skipping  humn security pss becuse the code cme from n ssistnt nd "looked fine." 

###### **`13` No environment vrible vlidtion** 

App boots even when  required secret is missing, silently flling bck to n insecure defult. 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
06 / 08
```

##### **VIBE CODER'S PRE-LAUNCH SECURITY CHECKLIST** 

- vv No secrets hrdcoded — ll in env vrs / Every input vlidted server-side, not just secrets mnger client-side 

- v Every route checks ownership / role, not just v login sttus 

   - Debug mode off, generic error messges in production 

- vv All DB queries prmeterized — zero stringRte limiting on login, OTP, nd psswordbuilt queries reset routes 

- v Every AI-suggested pckge verified before v instll 

   - Every externl cll wrpped in rel error hndling 

- vv Full red-through of AI-generted Logging + bsic lerting on sensitive uth/pyment code ctions 

- v HTTPS enforced everywhere, dmin routes v gted seprtely 

   - Checkout totls reclculted server-side, webhooks verified 

- No leftover test ccounts, docs endpoints locked down 

#### **QUICK TOOLS TO CLOSE EACH GAP** 

No need to build ny of this yourself — these re the stndrd, widely-used tools tht fix the risks bove in minutes. 

## <u>s</u> **Secrets & Config** <u>e</u> **Auth & Sessions** <u>e</u> **Dependency Sfety** 

Doppler / Infisicl / Vult AWS Secrets Mnger python-dotenv + .gitignore GitHub secret scnning 

Auth0 / Clerk / Supbse Auth NextAuth.js / FstAPIUsers PyJWT / jose JWT hndling) bcrypt / rgon2-cffi 

Snyk / Dependbot pip-udit / npm udit Socket.dev (supply-chin risk) Renovte (uto version PRs) 

# <u>e</u> **Rte Limiting** s **Logging & Alerts** e 

###### **Code & Query Sfety** 

slowpi FstAPI / expressrte-limit Cloudflre / API Gtewy throttling Redis-bcked token buckets 

Upstsh Rtelimit 

Sentry (errors) / Better Stck 

Dtdog / Grfn  Loki 

- Structured logging (structlog, pino) 

- UptimeRobot for bsic lerts 

SQLAlchemy / Prism (prmeterized ORM Zod / Pydntic (input vlidtion) 

Semgrep / Bndit (sttic nlysis) 

GitHub CodeQL scnning 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
07 / 08
```

#### **EXCUSES vs REALITY** 

**EXC U S E** 

###### **"It's just n MVP, no one's wtching yet."** 

**EXC U S E** 

###### **"AI wrote it, so it's probbly fine."** 

**Relity:** bots scn the entire public internet for open endpoints nd exposed keys within hours of  domin going live  MVPs get hit constntly. 

**Relity:** AI optimizes for code tht runs nd psses the demo — not code tht resists someone ctively trying to brek it. 

**EXC U S E** 

###### **"I'll dd security once I hve rel users."** 

**EXC U S E** 

###### **"My repo is privte, so it's sfe."** 

**Relity:** "rel users" is exctly the moment there's something worth steling — retrofitting security fter  brech is fr more expensive. 

**Relity:**  privte repo doesn't protect  public API — ttckers hit your live endpoints directly, they don't need your source code. 

**EXC U S E** 

###### **"I tested it myself, it's fine."** 

**EXC U S E** 

###### **"We'll hrden it properly in v2."** 

**Relity:** mnul testing checks tht fetures work — it rrely tries to brek uth, inject bd input, or hit n endpoint out of order the wy n ttcker would. 

**Relity:** user dt, trust, nd reputtion re ll on the line from v1 onwrd —  brech there still costs you long before v2 ships. 

###### **T H E O N E - L I N E TA K E AW AY** 

AI writes code tht works. It doesn't utomticlly write code tht's sfe — tht prt is still your job. None of the fixes bove require  security bckground: they're hbits. Vlidte on the server, check ownership on every route, prmeterize every query, nd red the security-sensitive lines before you merge. 

**Run this checklist before every lunch, nd "vibe coded" stops mening "unreviewed."** 

**Dileep Kumar** |  Instagram: @dileep.aidev 

```
08 / 08
```

