export async function onRequestPost(context) {
    try {
        const { pin } = await context.request.json();

        const SECRET_PIN = context.env.SECRET_PIN;
        const KOHA_USER = context.env.KOHA_USER;
        const KOHA_PASS = context.env.KOHA_PASS;

        if (!pin || pin !== SECRET_PIN) {
            return new Response(JSON.stringify({ success: false, error: "Invalid administrative passcode." }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        return new Response(JSON.stringify({
            success: true,
            user: KOHA_USER,
            pass: KOHA_PASS
        }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        });

    } catch (err) {
        return new Response(JSON.stringify({ success: false, error: "Internal server error." }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}