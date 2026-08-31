const DEFAULT_KOHA_PATH = "/cgi-bin/koha/mainpage.pl";

function getSetCookies(headers) {
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie() || [];
    if (typeof headers.getAll === "function") return headers.getAll("Set-Cookie") || [];
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
        values[name] = input.match(valuePattern)?.[1] || "";
    }
    return values;
}

function addTunnelAuth(headers, env) {
    // Optional Cloudflare Access service-token authentication for the private
    // Koha hostname. The values remain Cloudflare secrets and never reach the browser.
    if (env.KOHA_ACCESS_CLIENT_ID && env.KOHA_ACCESS_CLIENT_SECRET) {
        headers.set("CF-Access-Client-Id", env.KOHA_ACCESS_CLIENT_ID);
        headers.set("CF-Access-Client-Secret", env.KOHA_ACCESS_CLIENT_SECRET);
    }
}

function rewriteSessionCookie(rawCookie) {
    return rawCookie
        .replace(/;\s*Domain=[^;]+/gi, "")
        .replace(/;\s*Path=[^;]*/gi, "; Path=/koha")
        .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax");
}

export async function onRequestPost(context) {
    try {
        const { pin } = await context.request.json();
        const { SECRET_PIN, KOHA_USER, KOHA_PASS, KOHA_BASE_URL } = context.env;

        if (!pin || pin !== SECRET_PIN) {
            return new Response(JSON.stringify({ success: false, error: "Invalid administrative passcode." }), {
                status: 401,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        if (!KOHA_USER || !KOHA_PASS || !KOHA_BASE_URL) {
            console.error("Required Cloudflare variables are missing: KOHA_USER, KOHA_PASS or KOHA_BASE_URL.");
            return new Response(JSON.stringify({ success: false, error: "Koha authentication is not configured." }), {
                status: 500,
                headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
            });
        }

        const baseUrl = new URL(KOHA_BASE_URL);
        const loginUrl = new URL(DEFAULT_KOHA_PATH, baseUrl);
        const upstreamHeaders = new Headers({
            "Accept": "text/html,application/xhtml+xml",
            "Cache-Control": "no-cache"
        });
        addTunnelAuth(upstreamHeaders, context.env);

        const loginPage = await fetch(loginUrl, {
            method: "GET",
            redirect: "manual",
            headers: upstreamHeaders
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

        for (const [name, value] of Object.entries(hidden)) form.set(name, value);
        form.set("login_userid", KOHA_USER);
        form.set("login_password", KOHA_PASS);
        form.set("login_op", "cud-login");
        if (!form.has("koha_login_context")) form.set("koha_login_context", "intranet");

        const postHeaders = new Headers({
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml",
            "Cookie": cookieHeader(initialCookies),
            "Referer": loginUrl.toString()
        });
        addTunnelAuth(postHeaders, context.env);

        const kohaLogin = await fetch(loginUrl, {
            method: "POST",
            redirect: "manual",
            headers: postHeaders,
            body: form.toString()
        });

        const responseCookies = getSetCookies(kohaLogin.headers);
        const allCookies = [...initialCookies, ...responseCookies];
        const location = kohaLogin.headers.get("Location") || "";
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

        const response = new Response(JSON.stringify({
            success: true,
            redirect: "/koha/cgi-bin/koha/mainpage.pl"
        }), {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer"
            }
        });

        // Only the Koha session is handed to the browser. Koha credentials remain
        // exclusively inside Cloudflare environment variables.
        for (const rawCookie of allCookies) {
            response.headers.append("Set-Cookie", rewriteSessionCookie(rawCookie));
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
