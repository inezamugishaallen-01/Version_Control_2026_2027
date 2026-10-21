const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();
const auth = getAuth();

function requireOwner(request) {
  if (!request.auth || request.auth.token.role !== "owner") {
    throw new HttpsError("permission-denied", "Only the website owner can perform this action.");
  }
}
function requireOwnerOrAdmin(request) {
  if (!request.auth || !["owner", "admin"].includes(request.auth.token.role)) {
    throw new HttpsError("permission-denied", "Administrator permission required.");
  }
}
function cleanEmail(value) {
  if (typeof value !== "string") throw new HttpsError("invalid-argument", "A valid email is required.");
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpsError("invalid-argument", "Enter a valid email address.");
  }
  return email;
}
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
async function audit(actorUid, action, details = {}) {
  await db.collection("auditLogs").add({
    actorUid, action, details,
    createdAt: FieldValue.serverTimestamp()
  });
}

// Owner creates a one-use invitation. The raw token is returned only once.
exports.createInvitation = onCall({ enforceAppCheck: false }, async (request) => {
  requireOwner(request);
  const email = cleanEmail(request.data?.email);
  const role = request.data?.role;
  if (!["admin", "member", "guest"].includes(role)) {
    throw new HttpsError("invalid-argument", "Role must be admin, member, or guest.");
  }
  if (role === "admin" && request.data?.confirmAdmin !== true) {
    throw new HttpsError("failed-precondition", "Confirm that this person should be a limited administrator.");
  }

  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const ref = db.collection("invitations").doc(tokenHash);
  await ref.create({
    email, role, createdBy: request.auth.uid,
    createdAt: FieldValue.serverTimestamp(),
    expiresAt: Timestamp.fromMillis(Date.now() + 7 * 24 * 60 * 60 * 1000),
    used: false
  });
  await audit(request.auth.uid, "invitation_created", { email, role });
  return { token, email, role, expiresInDays: 7 };
});

// New user signs up with Firebase Auth then redeems the one-use token.
// Their verified email must match the invitation.
exports.acceptInvitation = onCall({ enforceAppCheck: false }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  if (request.auth.token.email_verified !== true) {
    throw new HttpsError("failed-precondition", "Verify your email before accepting an invitation.");
  }
  const token = request.data?.token;
  if (typeof token !== "string" || token.length < 30 || token.length > 200) {
    throw new HttpsError("invalid-argument", "Invitation token is invalid.");
  }

  const tokenHash = hashToken(token);
  const ref = db.collection("invitations").doc(tokenHash);
  const result = await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new HttpsError("not-found", "Invitation not found or already used.");
    const invite = snap.data();
    if (invite.used) throw new HttpsError("already-exists", "This invitation has already been used.");
    if (invite.expiresAt.toMillis() < Date.now()) throw new HttpsError("deadline-exceeded", "Invitation has expired.");
    if (String(request.auth.token.email || "").toLowerCase() !== invite.email) {
      throw new HttpsError("permission-denied", "Sign in using the email address that was invited.");
    }
    tx.update(ref, { used: true, usedBy: request.auth.uid, usedAt: FieldValue.serverTimestamp() });
    return { role: invite.role, email: invite.email };
  });

  // Never permit invitation role "owner". Only trusted owner bootstrap can set owner.
  await auth.setCustomUserClaims(request.auth.uid, { role: result.role });
  await db.collection("users").doc(request.auth.uid).set({
    email: result.email,
    role: result.role,
    displayName: request.auth.token.name || "",
    createdAt: FieldValue.serverTimestamp(),
    invitedBy: "owner"
  }, { merge: true });
  await audit(request.auth.uid, "invitation_accepted", { role: result.role });
  return { role: result.role, message: "Invitation accepted. Refresh your sign-in token to load your permissions." };
});

// Owner can change a person's role, but cannot assign owner via this function.
exports.setFamilyRole = onCall({ enforceAppCheck: false }, async (request) => {
  requireOwner(request);
  const uid = request.data?.uid;
  const role = request.data?.role;
  if (typeof uid !== "string" || uid.length < 5) {
    throw new HttpsError("invalid-argument", "A valid user ID is required.");
  }
  if (!["admin", "member", "guest"].includes(role)) {
    throw new HttpsError("invalid-argument", "Role must be admin, member, or guest. Owner cannot be assigned here.");
  }
  if (uid === request.auth.uid) {
    throw new HttpsError("failed-precondition", "Use the owner account's trusted recovery process for owner changes.");
  }
  const user = await auth.getUser(uid);
  await auth.setCustomUserClaims(uid, { ...(user.customClaims || {}), role });
  await db.collection("users").doc(uid).set({ role, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  await audit(request.auth.uid, "role_changed", { targetUid: uid, role });
  return { uid, role };
});

// Owner can revoke a family account immediately.
exports.disableFamilyAccount = onCall({ enforceAppCheck: false }, async (request) => {
  requireOwner(request);
  const uid = request.data?.uid;
  if (typeof uid !== "string" || uid.length < 5 || uid === request.auth.uid) {
    throw new HttpsError("invalid-argument", "Provide another valid user ID.");
  }
  await auth.updateUser(uid, { disabled: true });
  await audit(request.auth.uid, "account_disabled", { targetUid: uid });
  return { uid, disabled: true };
});

// Admins may moderate posts, but cannot invite or change account roles.
exports.deleteFamilyPost = onCall({ enforceAppCheck: false }, async (request) => {
  requireOwnerOrAdmin(request);
  const postId = request.data?.postId;
  if (typeof postId !== "string" || postId.length > 150) {
    throw new HttpsError("invalid-argument", "A valid post ID is required.");
  }
  await db.collection("familyPosts").doc(postId).delete();
  await audit(request.auth.uid, "family_post_deleted", { postId });
  return { deleted: true };
});
