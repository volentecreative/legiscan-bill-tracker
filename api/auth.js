// /api/auth.js
export default async function handler(req, res) {
  const validPassword = process.env.DASHBOARD_PASSWORD || 'changeme123';
  
  if (req.method === 'POST') {
    const { password } = req.body;
    
    if (password === validPassword) {
      return res.status(200).json({ success: true });
    } else {
      return res.status(401).json({ success: false, error: 'Invalid password' });
    }
  }
  
  return res.status(405).json({ error: 'Method not allowed' });
}
