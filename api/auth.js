// /api/auth.js
const crypto = require('crypto');

// In-memory storage for rate limiting
const loginAttempts = new Map();

const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

function generateSessionToken(password) {
  // Create a signed session token that includes expiry
  const expiresAt = Date.now() + SESSION_DURATION;
  const data = JSON.stringify({ exp: expiresAt });
  
  // Sign the data with the password as secret
  const hmac = crypto.createHmac('sha256', password);
  hmac.update(data);
  const signature = hmac.digest('hex');
  
  // Combine data and signature
  const token = Buffer.from(data).toString('base64') + '.' + signature;
  return token;
}

function verifySessionToken(token, password) {
  try {
    const [dataBase64, signature] = token.split('.');
    if (!dataBase64 || !signature) return { valid: false };
    
    const data = Buffer.from(dataBase64, 'base64').toString('utf8');
    
    // Verify signature
    const hmac = crypto.createHmac('sha256', password);
    hmac.update(data);
    const expectedSignature = hmac.digest('hex');
    
    if (signature !== expectedSignature) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    // Check expiry
    const parsed = JSON.parse(data);
    if (Date.now() > parsed.exp) {
      return { valid: false, error: 'Session expired' };
    }
    
    return { valid: true };
  } catch (error) {
    return { valid: false, error: 'Invalid token format' };
  }
}

function checkRateLimit(ip) {
  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: null };
  
  if (attempts.lockedUntil && Date.now() < attempts.lockedUntil) {
    const remainingMinutes = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
    return {
      allowed: false,
      message: `Too many failed attempts. Try again in ${remainingMinutes} minute(s).`
    };
  }
  
  if (attempts.lockedUntil && Date.now() >= attempts.lockedUntil) {
    attempts.count = 0;
    attempts.lockedUntil = null;
  }
  
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

module.exports = async function handler(req, res) {
  const validPassword = process.env.DASHBOARD_PASSWORD;
  
  if (!validPassword) {
    return res.status(500).json({ 
      success: false, 
      error: 'Server configuration error: DASHBOARD_PASSWORD not set' 
    });
  }
  
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.socket.remoteAddress || 
             'unknown';
  
  // POST - Login
  if (req.method === 'POST') {
    const { password } = req.body;
    
    const rateLimitCheck = checkRateLimit(ip);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ 
        success: false, 
        error: rateLimitCheck.message 
      });
    }
    
    if (password === validPassword) {
      const sessionToken = generateSessionToken(validPassword);
      resetAttempts(ip);
      
      res.setHeader('Set-Cookie', [
        `session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`
      ]);
      
      return res.status(200).json({ success: true });
    } else {
      recordFailedAttempt(ip);
      
      const attempts = loginAttempts.get(ip);
      const remainingAttempts = MAX_ATTEMPTS - attempts.count;
      
      return res.status(401).json({ 
        success: false, 
        error: `Invalid password. ${remainingAttempts} attempt(s) remaining.`
      });
    }
  }
  
  // GET - Check session
  if (req.method === 'GET') {
    const cookies = req.headers.cookie || '';
    const sessionMatch = cookies.match(/session=([^;]+)/);
    
    if (!sessionMatch) {
      return res.status(401).json({ authenticated: false });
    }
    
    const verification = verifySessionToken(sessionMatch[1], validPassword);
    
    if (verification.valid) {
      return res.status(200).json({ authenticated: true });
    } else {
      return res.status(401).json({ authenticated: false });
    }
  }
  
  // DELETE - Logout
  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', [
      'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    ]);
    
    return res.status(200).json({ success: true });
  }
  
  return res.status(405).json({ error: 'Method not allowed' });
};

// Export verification function for use in other endpoints
module.exports.verifySession = function(req) {
  const validPassword = process.env.DASHBOARD_PASSWORD;
  
  if (!validPassword) {
    return { valid: false, error: 'Server configuration error' };
  }
  
  const cookies = req.headers.cookie || '';
  const sessionMatch = cookies.match(/session=([^;]+)/);
  
  if (!sessionMatch) {
    return { valid: false, error: 'No session cookie' };
  }
  
  return verifySessionToken(sessionMatch[1], validPassword);
};
