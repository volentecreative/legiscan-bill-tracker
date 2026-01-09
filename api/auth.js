// /api/auth.js
import crypto from 'crypto';

// Simple in-memory session store (use Redis/database in production)
const sessions = new Map();
const loginAttempts = new Map();

const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function checkRateLimit(ip) {
  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: null };
  
  // Check if locked out
  if (attempts.lockedUntil && Date.now() < attempts.lockedUntil) {
    const remainingMinutes = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
    return {
      allowed: false,
      message: `Too many failed attempts. Try again in ${remainingMinutes} minute(s).`
    };
  }
  
  // Reset if lockout expired
  if (attempts.lockedUntil && Date.now() >= attempts.lockedUntil) {
    attempts.count = 0;
    attempts.lockedUntil = null;
  }
  
  // Check attempt count
  if (attempts.count >= MAX_ATTEMPTS) {
    attempts.lockedUntil = Date.now() + LOCKOUT_TIME;
    loginAttempts.set(ip, attempts);
    return {
      allowed: false,
      message: `Too many failed attempts. Locked out for ${Math.ceil(LOCKOUT_TIME / 60000)} minutes.`
    };
  }
  
  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: null };
  attempts.count++;
  loginAttempts.set(ip, attempts);
}

function resetAttempts(ip) {
  loginAttempts.delete(ip);
}

export default async function handler(req, res) {
  const validPassword = process.env.DASHBOARD_PASSWORD;
  
  if (!validPassword) {
    return res.status(500).json({ 
      success: false, 
      error: 'Server configuration error' 
    });
  }
  
  // Get client IP for rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.socket.remoteAddress || 
             'unknown';
  
  if (req.method === 'POST') {
    const { password } = req.body;
    
    // Rate limit check
    const rateLimitCheck = checkRateLimit(ip);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ 
        success: false, 
        error: rateLimitCheck.message 
      });
    }
    
    // Verify password
    if (password === validPassword) {
      // Generate session token
      const sessionToken = generateSessionToken();
      const expiresAt = Date.now() + SESSION_DURATION;
      
      // Store session
      sessions.set(sessionToken, {
        createdAt: Date.now(),
        expiresAt,
        ip
      });
      
      // Reset failed attempts on success
      resetAttempts(ip);
      
      // Clean up old sessions (simple cleanup)
      for (const [token, session] of sessions.entries()) {
        if (Date.now() > session.expiresAt) {
          sessions.delete(token);
        }
      }
      
      // Set HttpOnly, Secure cookie
      res.setHeader('Set-Cookie', [
        `session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`
      ]);
      
      return res.status(200).json({ success: true });
    } else {
      // Record failed attempt
      recordFailedAttempt(ip);
      
      const attempts = loginAttempts.get(ip);
      const remainingAttempts = MAX_ATTEMPTS - attempts.count;
      
      return res.status(401).json({ 
        success: false, 
        error: `Invalid password. ${remainingAttempts} attempt(s) remaining.`
      });
    }
  }
  
  if (req.method === 'GET') {
    // Check session validity
    const cookies = req.headers.cookie || '';
    const sessionMatch = cookies.match(/session=([^;]+)/);
    
    if (!sessionMatch) {
      return res.status(401).json({ authenticated: false });
    }
    
    const sessionToken = sessionMatch[1];
    const session = sessions.get(sessionToken);
    
    if (!session || Date.now() > session.expiresAt) {
      if (session) sessions.delete(sessionToken);
      return res.status(401).json({ authenticated: false });
    }
    
    return res.status(200).json({ authenticated: true });
  }
  
  if (req.method === 'DELETE') {
    // Logout
    const cookies = req.headers.cookie || '';
    const sessionMatch = cookies.match(/session=([^;]+)/);
    
    if (sessionMatch) {
      sessions.delete(sessionMatch[1]);
    }
    
    res.setHeader('Set-Cookie', [
      'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    ]);
    
    return res.status(200).json({ success: true });
  }
  
  return res.status(405).json({ error: 'Method not allowed' });
}

// Export function to verify session (used by other endpoints)
export function verifySession(req) {
  const cookies = req.headers.cookie || '';
  const sessionMatch = cookies.match(/session=([^;]+)/);
  
  if (!sessionMatch) {
    return { valid: false, error: 'No session cookie' };
  }
  
  const sessionToken = sessionMatch[1];
  const session = sessions.get(sessionToken);
  
  if (!session) {
    return { valid: false, error: 'Invalid session' };
  }
  
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionToken);
    return { valid: false, error: 'Session expired' };
  }
  
  return { valid: true, session };
}
