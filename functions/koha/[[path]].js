const KOHA_BASE_URL = "http://92.4.70.3:8080";

const REQUEST_HEADERS = [
    "accept",
    "accept-language",
    "authorization",
    "content-type",
    "cookie",
    "origin",
    "referer",
    "user-agent"
];

const RESPONSE_HEADERS = [
    "cache-control",
    "content-language",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "location",
    "pragma",
    "vary",
    "www-authenticate"
];

function copyRequestHeaders(request) {
    const headers = new Headers();
    for (const name of REQUEST_HEADERS) {
        const value = request.headers.get(name);
        if (value) headers.set(name, value);
    }
    return headers;
}

function rewriteLocation(location, publicOrigin) {
    if (!location) return null;
    try {
        const absolute = new URL(location, KOHA_BASE_URL);
        return `${publicOrigin}/koha${absolute.pathname}${absolute.search}${absolute.hash}`;
    } catch {
        return location.startsWith("/") ? `/koha${location}` : location;
    }
}

function rewriteHtml(html) {
    const prefixes = [
        "/cgi-bin/koha/",
        "/intranet-tmpl/",
        "/opac-tmpl/",
        "/api/v1/",
        "/svc/"
    ];

    for (const prefix of prefixes) {
        html = html.split(`\"${prefix}`).join(`\"/koha${prefix}`);
        html = html.split(`'${prefix}`).join(`'/koha${prefix}`);
        html = html.split(`(${prefix}`).join(`(/koha${prefix}`);
        html = html.split(`=${prefix}`).join(`=/koha${prefix}`);
    }

    // Koha may emit absolute links to its own origin.
    html = html.split(`${KOHA_BASE_URL}/`).join(`/koha/`);
    return html;
}

function copySetCookies(source, target) {
    const cookies = typeof source.getAll === "function"
        ? source.getAll("Set-Cookie")
        : (typeof source.getSetCookie === "function" ? source.getSetCookie() : []);

    for (const cookie of cookies || []) {
        const rewritten = cookie
            .replace(/;\s*Domain=[^;]+/gi, "")
            .replace(/;\s*Path=[^;]*/gi, "; Path=/koha")
            .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax");
        target.append("Set-Cookie", rewritten);
    }
}

export async function onRequest(context) {
    try {
        const incomingUrl = new URL(context.request.url);
        const routePath = context.params.path;
        const path = Array.isArray(routePath) ? routePath.join("/") : (routePath || "");
        const upstreamUrl = new URL(`/${path}`, KOHA_BASE_URL);
        upstreamUrl.search = incomingUrl.search;

        const headers = copyRequestHeaders(context.request);
        headers.set("Host", new URL(KOHA_BASE_URL).host);
        headers.set("X-Forwarded-Proto", "https");
        headers.set("X-Forwarded-Host", incomingUrl.host);

        const upstream = await fetch(upstreamUrl.toString(), {
            method: context.request.method,
            headers,
            body: ["GET", "HEAD"].includes(context.request.method) ? undefined : context.request.body,
            redirect: "manual"
        });

        const responseHeaders = new Headers();
        for (const name of RESPONSE_HEADERS) {
            const value = upstream.headers.get(name);
            if (value && name.toLowerCase() !== "location") responseHeaders.set(name, value);
        }

        const location = rewriteLocation(upstream.headers.get("Location"), incomingUrl.origin);
        if (location) responseHeaders.set("Location", location);
        copySetCookies(upstream.headers, responseHeaders);

        responseHeaders.set("Cache-Control", "no-store");
        responseHeaders.set("X-Content-Type-Options", "nosniff");

        const contentType = upstream.headers.get("Content-Type") || "";
        if (contentType.includes("text/html")) {
            const html = rewriteHtml(await upstream.text());
            return new Response(html, {
                status: upstream.status,
                statusText: upstream.statusText,
                headers: responseHeaders
            });
        }

        return new Response(upstream.body, {
            status: upstream.status,
            statusText: upstream.statusText,
            headers: responseHeaders
        });
    } catch (err) {
        console.error("Koha proxy error", err);
        return new Response("Koha service is temporarily unavailable.", {
            status: 502,
            headers: { "Content-Type": "text/plain; charset=UTF-8", "Cache-Control": "no-store" }
        });
    }
}
