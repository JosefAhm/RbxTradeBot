import { getServerSession } from "./session"

export async function getAdminContext() {
  const session = await getServerSession()
  const adminUsername = process.env.BOT_ADMIN_USERNAME
  if (!adminUsername) {
    throw new Error("BOT_ADMIN_USERNAME env var is required")
  }

  const isAdmin = !!session.user && session.user.username.toLowerCase() === adminUsername.toLowerCase()

  return { session, isAdmin, adminUsername }
}
