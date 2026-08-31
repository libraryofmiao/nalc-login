const KOHA_BASE_URL = "http://92.4.70.3:8080";
const KOHA_LOGIN_PATH = "/cgi-bin/koha/mainpage.pl";

function getSetCookies(headers) {
    if (typeof headers.getAll === "function") return headers.getAll("Set-Cookie") || [];
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie() || [];
    const value = headers.get("Set-Cookie");
    return value ? [value] : [];
}

function cookieHeader(cookies) {
    return cookies.map((cookie) => cookie.split(";", 1)[0]).filter(Boolean).join("; ");
}

function extractHiddenInputs(html) {
    const values = {};
    const inputPattern = /<input\b[^>]*>/gi;
    const namePattern = /\bname\s*=\s*["']([^"']+)["']/i;
    const valuePattern = /\bvalue\s*=\s*["']([^"']*)["']/i;

    for (const input of html.match(inputPattern) || []) {
        const name = input.match(namePattern)?.[1];
        if (!name) continue;
        const value = input.match(valuePattern)?.[1] || "";
        values[name] = value;
    }
    return values;
}

export async function onRequestPost(context) {
    try {
        const { pin } = await context.request.json();
        const { SECRET_PIN, KOHA_USER, KOHA_PASS } = context.env;

        if (!pin || pin !== SECRET_PIN) {
            return new Response(JSON.stringify({ success: false, error: "Invalid administrative passcode." }), {
                status: 401,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        if (!KOHA_USER || !KOHA_PASS) {
            console.error("KOHA_USER or KOHA_PASS is not configured in Cloudflare environment variables.");
            return new Response(JSON.stringify({ success: false, error: "Koha authentication is not configured." }), {
                status: 500,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        // First obtain the Koha login page so that any hidden fields/tokens and
        // the initial session cookie are carried into the authentication POST.
        const loginPage = await fetch(new URL(KOHA_LOGIN_PATH, KOHA_BASE_URL), {
            method: "GET",
            redirect: "manual",
            headers: {
                "Accept": "text/html,application/xhtml+xml",
                "Cache-Control": "no-cache"
            }
        });

        if (!loginPage.ok) {
            console.error("Koha login page returned", loginPage.status);
            return new Response(JSON.stringify({ success: false, error: "Unable to reach the Koha login service." }), {
                status: 502,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        const loginHtml = await loginPage.text();
        const initialCookies = getSetCookies(loginPage.headers);
        const hidden = extractHiddenInputs(loginHtml);
        const form = new URLSearchParams();

        for (const [name, value] of Object.entries(hidden)) {
            form.set(name, value);
        }
        form.set("login_userid", KOHA_USER);
        form.set("login_password", KOHA_PASS);
        form.set("login_op", "cud-login");
        if (!form.has("koha_login_context")) form.set("koha_login_context", "intranet");

        const kohaLogin = await fetch(new URL(KOHA_LOGIN_PATH, KOHA_BASE_URL), {
            method: "POST",
            redirect: "manual",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml",
                "Cookie": cookieHeader(initialCookies),
                "Referer": new URL(KOHA_LOGIN_PATH, KOHA_BASE_URL).toString()
            },
            body: form.toString()
        });

        const responseCookies = getSetCookies(kohaLogin.headers);
        const allCookies = [...initialCookies, ...responseCookies];
        const location = kohaLogin.headers.get("Location") || "";

        // Koha normally returns a redirect after successful authentication.
        // Do not expose KOHA_USER or KOHA_PASS to the browser.
        const looksAuthenticated = kohaLogin.status >= 300 && kohaLogin.status < 400 &&
            (location.includes("mainpage.pl") || location.includes("/cgi-bin/koha/"));

        if (!looksAuthenticated) {
            const body = await kohaLogin.text();
            const failedLogin = /invalid|incorrect|login failed|authentication failed|try again/i.test(body);
            console.error("Koha authentication failed", kohaLogin.status, location);
            return new Response(JSON.stringify({
                success: false,
                error: failedLogin ? "Koha rejected the configured credentials." : "Koha authentication could not be completed."
            }), {
                status: 502,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        const response = new Response(null, {
            status: 302,
            headers: {
                "Location": "/koha/cgi-bin/koha/mainpage.pl",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer"
            }
        });

        // Store Koha's session cookie on the NALC/Cloudflare origin. The browser
        // will then send it back to the /koha proxy, which forwards it to Koha.
        for (const rawCookie of allCookies) {
            const rewritten = rawCookie
                .replace(/;\s*Domain=[^;]+/gi, "")
                .replace(/;\s*Path=[^;]*/gi, "; Path=/koha")
                .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax");
            response.headers.append("Set-Cookie", rewritten);
        }

        return response;
    } catch (err) {
        console.error("NALC login error", err);
        return new Response(JSON.stringify({ success: false, error: "Unable to complete Koha authentication." }), {
            status: 500,
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
        });
    }
}
