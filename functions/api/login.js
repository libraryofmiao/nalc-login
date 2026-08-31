const KOHA_LOGIN_PATH = "/cgi-bin/koha/mainpage.pl";

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=UTF-8",
            "Cache-Control": "no-store"
        }
    });
}

function getCookies(headers) {
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie() || [];
    const value = headers.get("set-cookie");
    return value ? [value] : [];
}

function cookieHeader(cookies) {
    return cookies.map((v) => v.split(";", 1)[0]).filter(Boolean).join("; ");
}

function hiddenFields(html) {
    const result = {};
    for (const tag of html.match(/<input\b[^>]*>/gi) || []) {
        const name = tag.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1];
        if (!name) continue;
        result[name] = tag.match(/\bvalue\s*=\s*["']([^"']*)["']/i)?.[1] || "";
    }
    return result;
}

export async function onRequestPost(context) {
    try {
        const body = await context.request.json().catch(() => ({}));
        const pin = String(body.pin || "").trim();
        const env = context.env;

        // Safe diagnostics: never return the actual secret values.
        const configured = {
            SECRET_PIN: Boolean(env.SECRET_PIN),
            KOHA_USER: Boolean(env.KOHA_USER),
            KOHA_PASS: Boolean(env.KOHA_PASS),
            KOHA_BASE_URL: Boolean(env.KOHA_BASE_URL)
        };

        if (!configured.SECRET_PIN) {
            console.error("SECRET_PIN binding is missing");
            return json({ success: false, error: "Administrative PIN is not configured." }, 500);
        }

        if (pin !== env.SECRET_PIN) {
            return json({ success: false, error: "Invalid administrative passcode." }, 401);
        }

        if (!configured.KOHA_USER || !configured.KOHA_PASS || !configured.KOHA_BASE_URL) {
            console.error("Koha bindings missing", configured);
            return json({
                success: false,
                error: "Koha authentication is not configured.",
                configured
            }, 500);
        }

        const base = new URL(env.KOHA_BASE_URL);
        const loginUrl = new URL(KOHA_LOGIN_PATH, base);

        const getHeaders = new Headers({
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0",
            "Cache-Control": "no-cache"
        });

        const page = await fetch(loginUrl, {
            method: "GET",
            headers: getHeaders,
            redirect: "manual"
        });

        if (!page.ok) {
            console.error("Koha GET failed", page.status);
            return json({ success: false, error: "Unable to reach Koha staff login.", status: page.status }, 502);
        }

        const html = await page.text();
        const cookies1 = getCookies(page.headers);
        const form = new URLSearchParams(hiddenFields(html));

        form.set("login_userid", env.KOHA_USER);
        form.set("login_password", env.KOHA_PASS);
        form.set("op", "cud-login");
        form.set("koha_login_context", "intranet");

        const postHeaders = new Headers({
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            Cookie: cookieHeader(cookies1),
            Referer: loginUrl.toString(),
            Origin: base.origin,
            "User-Agent": "Mozilla/5.0"
        });

        const result = await fetch(loginUrl, {
            method: "POST",
            headers: postHeaders,
            body: form.toString(),
            redirect: "manual"
        });

        const location = result.headers.get("Location") || "";
        const cookies2 = getCookies(result.headers);
        const allCookies = [...cookies1, ...cookies2];
        const target = location ? new URL(location, loginUrl) : null;
        const success = Boolean(
            target &&
            result.status >= 300 &&
            result.status < 400 &&
            target.pathname.startsWith("/cgi-bin/koha/")
        );

        if (!success) {
            const responseText = await result.text();
            console.error("Koha login rejected", {
                status: result.status,
                location,
                cookieNames: allCookies.map((c) => c.split("=", 1)[0]).join(","),
                bodyStart: responseText.slice(0, 200)
            });
            return json({
                success: false,
                error: "Koha rejected the staff login.",
                status: result.status
            }, 502);
        }

        const response = json({
            success: true,
            redirect: "/koha/cgi-bin/koha/mainpage.pl"
        });

        for (const raw of allCookies) {
            const cookie = raw
                .replace(/;\s*Domain=[^;]+/gi, "")
                .replace(/;\s*Path=[^;]*/gi, "; Path=/koha")
                .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax");
            response.headers.append("Set-Cookie", cookie);
        }

        return response;
    } catch (error) {
        console.error("NALC login exception", error);
        return json({ success: false, error: "Unable to complete Koha authentication." }, 500);
    }
}
