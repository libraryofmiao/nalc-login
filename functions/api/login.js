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
    if (env.KOHA_ACCESS_CLIENT_ID && env.KOHA_ACCESS_CLIENT_SECRET) {
        headers.set("CF-Access-Client-Id", env.KOHA_ACCESS_CLIENT_ID);
        headers.set("CF-Access-Client-Secret", env.KOHA_ACCESS_CLIENT_SECRET);
    }
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=UTF-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
        }
    });
}

export async function onRequestPost(context) {
    try {
        const body = await context.request.json().catch(() => ({}));
        const pin = String(body.pin || "").trim();
        const { SECRET_PIN, KOHA_USER, KOHA_PASS, KOHA_BASE_URL } = context.env;

        if (!SECRET_PIN || pin !== SECRET_PIN) {
            return json({ success: false, error: "Invalid administrative passcode." }, 401);
        }

        if (!KOHA_USER || !KOHA_PASS || !KOHA_BASE_URL) {
            console.error("Missing KOHA_USER, KOHA_PASS or KOHA_BASE_URL.");
            return json({ success: false, error: "Koha authentication is not configured." }, 500);
        }

        const baseUrl = new URL(KOHA_BASE_URL);
        baseUrl.pathname = baseUrl.pathname.replace(/\/$/, "");
        const loginUrl = new URL(DEFAULT_KOHA_PATH, baseUrl);

        const getHeaders = new Headers({
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
            "User-Agent": "Mozilla/5.0"
        });
        addTunnelAuth(getHeaders, context.env);

        const loginPage = await fetch(loginUrl, {
            method: "GET",
            redirect: "manual",
            headers: getHeaders
        });

        if (!loginPage.ok) {
            console.error("Koha login page returned", loginPage.status);
            return json({ success: false, error: "Unable to reach the Koha login service." }, 502);
        }

        const loginHtml = await loginPage.text();
        const initialCookies = getSetCookies(loginPage.headers);
        const hidden = extractHiddenInputs(loginHtml);
        const form = new URLSearchParams();

        for (const [name, value] of Object.entries(hidden)) form.set(name, value);

        form.set("login_userid", KOHA_USER);
        form.set("login_password", KOHA_PASS);
        form.set("op", "cud-login");
        form.set("login_op", "cud-login");
        form.set("koha_login_context", "intranet");

        const postHeaders = new Headers({
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            Cookie: cookieHeader(initialCookies),
            Referer: loginUrl.toString(),
            Origin: baseUrl.origin,
            "User-Agent": "Mozilla/5.0"
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
        const redirectTarget = new URL(location || "/", loginUrl);
        const authenticatedRedirect =
            kohaLogin.status >= 300 &&
            kohaLogin.status < 400 &&
            redirectTarget.pathname.startsWith("/cgi-bin/koha/") &&
            !/mainpage\.pl\?logout/i.test(location);

        if (!authenticatedRedirect) {
            const responseBody = await kohaLogin.text();
            const loginRejected = /invalid|incorrect|login failed|authentication failed|try again/i.test(responseBody);
            console.error("Koha authentication failed", {
                status: kohaLogin.status,
                location,
                cookies: allCookies.map((c) => c.split("=", 1)[0]).join(",")
            });
            return json({
                success: false,
                error: loginRejected
                    ? "Koha rejected the configured credentials."
                    : "Koha authentication could not be completed."
            }, 502);
        }

        const response = json({
            success: true,
            redirect: "/koha/cgi-bin/koha/mainpage.pl"
        });

        for (const rawCookie of allCookies) {
            const cookie = rawCookie
                .replace(/;\s*Domain=[^;]+/gi, "")
                .replace(/;\s*Path=[^;]*/gi, "; Path=/koha")
                .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax");
            response.headers.append("Set-Cookie", cookie);
        }

        return response;
    } catch (err) {
        console.error("NALC login error", err);
        return json({ success: false, error: "Unable to complete Koha authentication." }, 500);
    }
}
