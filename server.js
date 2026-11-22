const http = require("http");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");

const root = __dirname;
const contentFile = path.join(root, "gc-lace-content.json");
const defaultsFile = path.join(root, "gc-lace-data.js");
const usersFile = path.join(root, "gc-lace-users.json");
const port = Number(process.env.PORT) || 3000;
const sessions = new Map();
const studentDomain = "gordoncollege.edu.ph";
const googleClientId = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return { salt, hash };
}

function verifyPassword(password, account) {
    if (!account || typeof account.salt !== "string" || typeof account.hash !== "string") return false;
    const storedHash = Buffer.from(account.hash, "hex");
    if (storedHash.length !== 64) return false;
    return crypto.timingSafeEqual(storedHash, crypto.scryptSync(password, account.salt, 64));
}

function readUsers() {
    if (!fs.existsSync(usersFile)) return [];
    return JSON.parse(fs.readFileSync(usersFile, "utf8"));
}

function writeUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function getCookies(request) {
    return Object.fromEntries((request.headers.cookie || "").split(";")
        .map(part => part.trim().split("="))
        .filter(parts => parts.length === 2)
        .map(([name, value]) => [name, decodeURIComponent(value)]));
}

function currentUser(request) {
    const token = getCookies(request).gc_lace_session;
    const account = token ? sessions.get(token) : null;
    return account || null;
}

function setSession(request, response, account) {
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, account);
    const secure = request.socket.encrypted || request.headers["x-forwarded-proto"] === "https";
    response.setHeader("Set-Cookie", "gc_lace_session=" + token + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000" + (secure ? "; Secure" : ""));
}

function readDefaults() {
    const source = fs.readFileSync(defaultsFile, "utf8");
    const match = source.match(/=\s*(\{[\s\S]*\})\s*;\s*$/);
    if (!match) throw new Error("Could not read default website content.");
    return vm.runInNewContext("(" + match[1] + ")");
}

function readContent() {
    if (fs.existsSync(contentFile)) {
        return JSON.parse(fs.readFileSync(contentFile, "utf8"));
    }
    const defaults = readDefaults();
    fs.writeFileSync(contentFile, JSON.stringify(defaults, null, 2));
    return defaults;
}

function writeContent(data) {
    fs.writeFileSync(contentFile, JSON.stringify(data, null, 2));
}

function sendJson(response, status, value, request) {
    const origin = request && request.headers.origin;
    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": origin || "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
        "Access-Control-Allow-Credentials": "true",
        "Cache-Control": "no-store"
    });
    response.end(JSON.stringify(value));
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let body = "";
        request.setEncoding("utf8");
        request.on("data", chunk => {
            body += chunk;
            if (body.length > 5_000_000) {
                reject(new Error("Request is too large."));
                request.destroy();
            }
        });
        request.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (error) {
                reject(new Error("Invalid JSON."));
            }
        });
        request.on("error", reject);
    });
}

function validateContent(data) {
    if (!data || typeof data !== "object" ||
        !data.hero || typeof data.hero.title !== "string" ||
        typeof data.hero.description !== "string") {
        throw new Error("Invalid website content.");
    }
    ["coursework", "courses", "announcements", "events", "questions"].forEach(key => {
        if (!Array.isArray(data[key])) throw new Error("Invalid " + key + " list.");
    });
    data.courses = data.courses.map(course => ({
        ...course,
        meetUrls: typeof course.meetUrls === "string" ? course.meetUrls :
            typeof course.meetUrl === "string" ? course.meetUrl : "",
        driveUrls: typeof course.driveUrls === "string" ? course.driveUrls :
            typeof course.driveUrl === "string" ? course.driveUrl : ""
    }));
}

const mimeTypes = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8"
};

const server = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, "http://" + request.headers.host);
    try {
        if (request.method === "OPTIONS") {
            response.writeHead(204, {
                "Access-Control-Allow-Origin": request.headers.origin || "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS",
                "Access-Control-Allow-Credentials": "true"
            });
            return response.end();
        }
        if (request.method === "GET" && requestUrl.pathname === "/api/auth/config") {
            return sendJson(response, 200, { clientId: googleClientId }, request);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/auth/google") {
            if (!googleClient) {
                return sendJson(response, 503, { error: "Google sign-in is not configured on this server." }, request);
            }
            const body = await readJson(request);
            if (typeof body.credential !== "string" || !body.credential) {
                return sendJson(response, 400, { error: "Google sign-in credential is required." }, request);
            }
            let payload;
            try {
                const ticket = await googleClient.verifyIdToken({
                    idToken: body.credential,
                    audience: googleClientId
                });
                payload = ticket.getPayload();
            } catch {
                return sendJson(response, 401, { error: "Google sign-in could not be verified. Please try again." }, request);
            }
            if (!payload) {
                return sendJson(response, 401, { error: "Google sign-in could not be verified. Please try again." }, request);
            }
            const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
            const emailDomain = email.split("@")[1];
            if (payload.email_verified !== true || emailDomain !== studentDomain) {
                return sendJson(response, 403, { error: "Sign in with a verified @" + studentDomain + " Google account." }, request);
            }
            const name = typeof payload.name === "string" && payload.name.trim()
                ? payload.name.trim()
                : email.split("@")[0];
            let picture = "";
            if (typeof payload.picture === "string") {
                try {
                    const pictureUrl = new URL(payload.picture);
                    if (pictureUrl.protocol === "https:") picture = pictureUrl.href;
                } catch {
                    picture = "";
                }
            }
            const users = readUsers();
            let account = users.find(user => user.email.toLowerCase() === email);
            const created = !account;
            if (account) {
                account.name = name;
                account.picture = picture;
            } else {
                account = { id: crypto.randomUUID(), name, email, picture, createdAt: new Date().toISOString() };
                users.push(account);
            }
            writeUsers(users);
            const user = {
                id: account.id,
                name: account.name,
                email: account.email,
                picture: account.picture || "",
                hasPassword: Boolean(account.salt && account.hash)
            };
            setSession(request, response, user);
            return sendJson(response, created ? 201 : 200, { ...user, created }, request);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/auth/signup") {
            const body = await readJson(request);
            const name = typeof body.name === "string" ? body.name.trim() : "";
            const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
            const password = typeof body.password === "string" ? body.password : "";
            const confirmedPassword = typeof body.confirmPassword === "string" ? body.confirmPassword : "";
            if (!name || !email || !password) throw new Error("Name, Gordon College email, and password are required.");
            if (email.split("@")[1] !== studentDomain) throw new Error("Only @" + studentDomain + " accounts can sign up.");
            if (password.length < 8) throw new Error("Password must be at least 8 characters.");
            if (!confirmedPassword || password !== confirmedPassword) throw new Error("Passwords do not match.");
            const users = readUsers();
            if (users.some(user => user.email.toLowerCase() === email)) throw new Error("An account already exists for this email.");
            const account = { id: crypto.randomUUID(), name, email, ...hashPassword(password), createdAt: new Date().toISOString() };
            users.push(account);
            writeUsers(users);
            const user = { id: account.id, name: account.name, email: account.email, picture: "", hasPassword: true };
            setSession(request, response, user);
            return sendJson(response, 201, user, request);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/auth/login") {
            const body = await readJson(request);
            const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
            const password = typeof body.password === "string" ? body.password : "";
            const account = readUsers().find(user => user.email.toLowerCase() === email);
            if (!account || account.email.split("@")[1] !== studentDomain || !verifyPassword(password, account)) {
                throw new Error("Invalid Gordon College account or password.");
            }
            const user = { id: account.id, name: account.name, email: account.email, picture: account.picture || "", hasPassword: true };
            setSession(request, response, user);
            return sendJson(response, 200, user, request);
        }
        if (request.method === "GET" && requestUrl.pathname === "/api/auth/me") {
            const user = currentUser(request);
            return sendJson(response, 200, user || null, request);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/auth/logout") {
            const token = getCookies(request).gc_lace_session;
            sessions.delete(token);
            const secure = request.socket.encrypted || request.headers["x-forwarded-proto"] === "https";
            response.setHeader("Set-Cookie", "gc_lace_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" + (secure ? "; Secure" : ""));
            return sendJson(response, 200, { ok: true }, request);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/auth/password") {
            const user = currentUser(request);
            if (!user) return sendJson(response, 401, { error: "Please sign in first." }, request);
            const body = await readJson(request);
            const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
            const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
            if (newPassword.length < 8) throw new Error("New password must be at least 8 characters.");
            const users = readUsers();
            const account = users.find(entry => entry.id === user.id);
            if (!account || !verifyPassword(currentPassword, account)) throw new Error("Current password is incorrect.");
            Object.assign(account, hashPassword(newPassword));
            writeUsers(users);
            return sendJson(response, 200, { ok: true }, request);
        }
        if (request.method === "GET" && requestUrl.pathname === "/api/content") {
            return sendJson(response, 200, readContent());
        }
        if (request.method === "PUT" && requestUrl.pathname === "/api/content") {
            const data = await readJson(request);
            validateContent(data);
            writeContent(data);
            return sendJson(response, 200, data);
        }
        if (request.method === "GET" && requestUrl.pathname === "/api/questions") {
            const content = readContent();
            return sendJson(response, 200, content.studentQuestions || []);
        }
        if (request.method === "POST" && requestUrl.pathname === "/api/questions") {
            const body = await readJson(request);
            const question = typeof body.question === "string" ? body.question.trim() : "";
            if (!question || question.length > 180) throw new Error("Question must be between 1 and 180 characters.");
            const content = readContent();
            content.studentQuestions = content.studentQuestions || [];
            content.studentQuestions.unshift({
                id: Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8),
                question,
                createdAt: new Date().toISOString()
            });
            writeContent(content);
            return sendJson(response, 201, content.studentQuestions[0]);
        }
        if (request.method === "PATCH" && requestUrl.pathname.startsWith("/api/coursework/")) {
            const id = decodeURIComponent(requestUrl.pathname.slice("/api/coursework/".length));
            const body = await readJson(request);
            if (typeof body.submitted !== "boolean") throw new Error("Submitted status is required.");
            const content = readContent();
            const item = content.coursework.find(coursework => coursework.id === id);
            if (!item) return sendJson(response, 404, { error: "Coursework not found." });
            item.status = body.submitted ? "submitted" : "pending";
            if (body.submitted && !item.submittedDate) {
                const today = new Date();
                item.submittedDate = [
                    today.getFullYear(),
                    String(today.getMonth() + 1).padStart(2, "0"),
                    String(today.getDate()).padStart(2, "0")
                ].join("-");
            } else if (!body.submitted) {
                item.submittedDate = "";
            }
            writeContent(content);
            return sendJson(response, 200, item);
        }

        const requestedPath = requestUrl.pathname === "/"
            ? "/StudyLace.html"
            : decodeURIComponent(requestUrl.pathname);
        const filePath = path.resolve(root, "." + requestedPath);
        if (filePath !== root && !filePath.startsWith(root + path.sep)) {
            return sendJson(response, 403, { error: "Forbidden." });
        }
        if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
            return sendJson(response, 404, { error: "Not found." });
        }
        response.writeHead(200, { "Content-Type": mimeTypes[path.extname(filePath)] || "application/octet-stream" });
        fs.createReadStream(filePath).pipe(response);
    } catch (error) {
        const status = error.message === "Invalid JSON." ||
            error.message.startsWith("Question") ||
            error.message.startsWith("Invalid website") ||
            error.message.includes("Gordon College") ||
            /password/i.test(error.message) ||
            error.message.includes("Passwords") ||
            error.message.includes("account already") ||
            error.message.includes("required") ? 400 : 500;
        sendJson(response, status, { error: error.message }, request);
    }
});

server.listen(port, () => {
    console.log("GC-LACE is running at http://localhost:" + port);
});
