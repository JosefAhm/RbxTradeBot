import { getIronSession } from "iron-session"
import { cookies } from "next/headers"

export type SessionData = {
	user?: {
		robloxUserId: number
		username: string
	}
	linkingAttempt?: {
		username: string
		robloxUserId: number
		code: string
		createdAt: number
	}
}

const sessionCookieName = "rbx_trade_session"

export function getSessionOptions() {
	const password = process.env.SESSION_SECRET
	if (!password) {
		throw new Error("SESSION_SECRET env var is required")
	}
	return {
		cookieName: sessionCookieName,
		password,
		cookieOptions: {
			sameSite: "lax" as const,
			secure: process.env.NODE_ENV === "production",
			httpOnly: true,
			path: "/"
		}
	}
}

export async function getServerSession() {
	const cookieStore = await cookies()
	return getIronSession<SessionData>(cookieStore, getSessionOptions())
}
