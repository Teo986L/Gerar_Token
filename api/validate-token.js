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

    // Handle OPTIONS request
    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    // Apenas POST permitido
    if (req.method !== 'POST') {
        return res.status(405).json({ 
            valid: false, 
            message: 'Método não permitido' 
        });
    }

    try {
        const { token } = req.body;

        // Tenta validar com todas as chaves disponíveis
        const secretsToTry = [
            { period: 365, key: SERVER_SECRETS['365'] },
            { period: 180, key: SERVER_SECRETS['180'] },
            { period: 90, key: SERVER_SECRETS['90'] },
            { period: 30, key: SERVER_SECRETS['30'] },
            { period: 7, key: SERVER_SECRETS['7'] },
        ];

        for (const secretData of secretsToTry) {
            if (!secretData.key) continue;
            
            try {
                const decoded = jwt.verify(token, secretData.key);
                return res.status(200).json({ 
                    valid: true, 
                    periodDays: secretData.period,
                    expiresAt: decoded.exp 
                });
            } catch (err) {
                // Continua tentando a próxima chave
                continue;
            }
        }

        return res.status(401).json({ 
            valid: false, 
            message: 'Token Inválido ou Expirado' 
        });

    } catch (error) {
        return res.status(400).json({ 
            valid: false, 
            message: 'Erro na requisição' 
        });
    }
}
