import express from "express";

const router = express.Router();

// Returns non-sensitive environment flags useful for debugging CORS/cookie issues
router.get("/env", (req, res) => {
  return res.json({
    nodeEnv: process.env.NODE_ENV || null,
    frontendUrl: process.env.FRONTEND_URL || null,
    jwtSecretSet: !!process.env.JWT_SECRET,
    geminiKeySet: !!process.env.GEMINI_API_KEY,
  });
});

// Set a test cookie to verify whether browser accepts cross-site cookies.
// This cookie is intentionally NOT httpOnly so it can be observed from the browser.
router.post("/set-cookie", (req, res) => {
  const isProd = process.env.NODE_ENV === "production";
  const cookieOptions = {
    maxAge: 60 * 60 * 1000, // 1 hour
    httpOnly: false,
    sameSite: isProd ? "none" : "lax",
    secure: isProd,
    path: "/",
  };

  res.cookie("jwt_test", "1", cookieOptions);
  return res.json({ message: "test cookie set", cookieOptions });
});

// Return cookies seen by the server for this request
router.get("/cookies", (req, res) => {
  return res.json({ cookies: req.cookies || {} });
});

export default router;
