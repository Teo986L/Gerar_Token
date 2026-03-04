import jwt from 'jsonwebtoken';

// Segredos do servidor
const SERVER_SECRETS = {
    '7': process.env.SECRET_KEY_7_DAYS,
    '30': process.env.SECRET_KEY_30_DAYS,
    '90': process.env.SECRET_KEY_90_DAYS,
    '180': process.env.SECRET_KEY_180_DAYS,
    '365': process.env.SECRET_KEY_365_DAYS,
};

export default async function handler(req, res) {
    // Configuração CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle OPTIONS request (preflight)
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Apenas POST permitido
    if (req.method !== 'POST') {
        return res.status(405).json({ 
            success: false, 
            message: 'Método não permitido' 
        });
    }

    try {
        const { periodDays } = req.body;
        const period = parseInt(periodDays);
        const secret = SERVER_SECRETS[period.toString()];

        if (!secret) {
            throw new Error('Período inválido ou chave não configurada.');
        }

        const expiresInSeconds = period * 24 * 60 * 60;
        const payload = { 
            period: periodDays, 
            jti: Math.random().toString(36).substring(2) + Date.now().toString(36) 
        };
        
        const token = jwt.sign(payload, secret, { expiresIn: expiresInSeconds });

        return res.status(200).json({ 
            success: true, 
            token, 
            periodDays: period 
        });
    } catch (error) {
        return res.status(400).json({ 
            success: false, 
            message: error.message 
        });
    }
}
