import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import mysql from 'mysql2/promise';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// MySQL connection pool for GTopia MariaDB
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'gtopia',
  port: Number(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 5000,
});

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} -> ${clientIp} | ${_res.statusCode}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Growtopia Login Server Running (GTopia Compatible)');
});

app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';

  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');
  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

const DEFAULT_CLIENT_DATA =
  'tankIDName|\ntankIDPass|\nrequestedName|Player\nf|1\nprotocol|210\nversion|4.35\ngame_version|4.35\nplatformID|0\nhash|123456789\nmac|02:00:00:00:00:00\nrid|00000000000000000000000000000000\nsid|00000000000000000000000000000000\nwk|00000000000000000000000000000000\ncountry|us\n';

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const _token = formData._token || '';
    const growId = (formData.growId || '').trim();
    const password = formData.password || '';
    const confirmPassword = formData.password_confirmation || '';
    const isRegister = formData.isRegister === '1' || Boolean(formData.password_confirmation);

    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.headers['x-real-ip'] ||
      req.socket.remoteAddress ||
      '127.0.0.1';

    let rawClientData = '';
    try {
      rawClientData = Buffer.from(_token, 'base64').toString('utf-8');
    } catch {
      rawClientData = _token;
    }

    if (!rawClientData || rawClientData.length < 5) {
      rawClientData = DEFAULT_CLIENT_DATA;
    } else {
      // Ensure essential fields exist if rawClientData is incomplete
      if (!rawClientData.includes('hash|')) {
        rawClientData += 'hash|123456789\n';
      }
      if (!rawClientData.includes('game_version|')) {
        rawClientData += 'game_version|4.35\n';
      }
      if (!rawClientData.includes('sid|') && !rawClientData.includes('wk|')) {
        rawClientData += 'sid|00000000000000000000000000000000\nwk|00000000000000000000000000000000\n';
      }
      if (!rawClientData.includes('mac|')) {
        rawClientData += 'mac|02:00:00:00:00:00\n';
      }
      if (!rawClientData.includes('rid|')) {
        rawClientData += 'rid|00000000000000000000000000000000\n';
      }
    }

    if (!growId) {
      return res.status(200).json({
        status: 'error',
        message: '`4Oops! ``Please enter a valid `wGrowID``.',
      });
    }

    if (!password) {
      return res.status(200).json({
        status: 'error',
        message: '`4Oops! ``Please enter a password.',
      });
    }

    if (growId.length < 3 || growId.length > 18) {
      return res.status(200).json({
        status: 'error',
        message: '`4Oops! ``GrowID must be between 3 and 18 characters long.',
      });
    }

    if (!/^[A-Za-z0-9#_\-]+$/.test(growId)) {
      return res.status(200).json({
        status: 'error',
        message: '`4Oops! ``GrowID can only contain letters, numbers, _, - and #.',
      });
    }

    if (isRegister) {
      if (password.length < 4 || password.length > 25) {
        return res.status(200).json({
          status: 'error',
          message: '`4Oops! ``Password must be between 4 and 25 characters long.',
        });
      }

      if (confirmPassword && password !== confirmPassword) {
        return res.status(200).json({
          status: 'error',
          message: '`4Oops! ``Passwords do not match.',
        });
      }

      // Check if GrowID already exists in Database
      try {
        const [existing] = await pool.execute<any[]>(
          'SELECT ID FROM players WHERE LOWER(Name) = LOWER(?) LIMIT 1',
          [growId]
        );

        if (existing && existing.length > 0) {
          return res.status(200).json({
            status: 'error',
            message: '`4Oops! ``That `wGrowID`` is already in use. Please choose another one.',
          });
        }

        // Insert into players table matching GTopia schema
        const formattedIp = String(clientIp).slice(0, 15);
        await pool.execute(
          'INSERT INTO players (Name, Password, GuestName, PlatformType, IP, CreationDate, LastSeenTime) VALUES (?, UNHEX(MD5(?)), ?, 0, ?, SYSDATE(), NOW())',
          [growId, password, growId, formattedIp]
        );
        console.log(`[REGISTER] Successfully registered account '${growId}' from IP ${formattedIp}`);
      } catch (dbErr) {
        console.error('[DB REGISTER ERROR]:', dbErr);
      }
    } else {
      // Login check against DB if available
      try {
        const [userRows] = await pool.execute<any[]>(
          'SELECT ID, Name FROM players WHERE LOWER(Name) = LOWER(?) AND Password = UNHEX(MD5(?)) LIMIT 1',
          [growId, password]
        );

        if (!userRows || userRows.length === 0) {
          const [nameCheck] = await pool.execute<any[]>(
            'SELECT ID FROM players WHERE LOWER(Name) = LOWER(?) LIMIT 1',
            [growId]
          );

          if (nameCheck && nameCheck.length > 0) {
            return res.status(200).json({
              status: 'error',
              message: '`4Unable to log on:`` That `wGrowID`` doesn\'t seem valid, or the password is wrong.',
            });
          }
        }
      } catch (dbErr) {
        console.warn('[DB LOGIN CHECK ERROR]:', dbErr);
      }
    }

    // GTopia C++ PlayerLoginDetail format:
    // loginInfo=<clientData>&growID=<growId>&password=<password>
    const cleanClientData = rawClientData.endsWith('\n') ? rawClientData.slice(0, -1) : rawClientData;
    const email = (formData.email || '').trim();
    const gtopiaPayload = `loginInfo=${cleanClientData}&growId=${growId}&password=${password}&email=${email}&reg=${isRegister ? 1 : 0}&has_reg=${isRegister ? 1 : 0}`;
    const token = Buffer.from(gtopiaPayload).toString('base64');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(
      JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
      }),
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData: string | undefined;
    let source = 'empty';
    const contentType = req.headers['content-type'] || '';

    if (typeof req.body === 'object' && req.body !== null) {
      const formData = req.body as Record<string, string>;

      if ('refreshToken' in formData || 'clientData' in formData) {
        refreshToken = formData.refreshToken;
        clientData = formData.clientData;
        source = contentType.includes('application/json') ? 'json/object' : 'form-urlencoded';
      } else if (Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || undefined;
        clientData = params.get('clientData') || undefined;
        if (refreshToken || clientData) {
          source = 'single-key-form-payload';
        }
      }
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      const params = new URLSearchParams(req.body);
      refreshToken = params.get('refreshToken') || undefined;
      clientData = params.get('clientData') || undefined;
      source = 'string/body-parser';
    }

    if ((!refreshToken || !clientData) && req.readable && !req.readableEnded) {
      const rawBody = await new Promise<string>((resolve, reject) => {
        let rawPayload = '';
        req.on('data', (chunk: Buffer | string) => {
          rawPayload += chunk.toString();
        });
        req.on('end', () => resolve(rawPayload));
        req.on('error', reject);
      });

      if (rawBody) {
        const params = new URLSearchParams(rawBody);
        refreshToken = params.get('refreshToken') || refreshToken;
        clientData = params.get('clientData') || clientData;
        if (refreshToken || clientData) {
          source = 'raw-stream';
        }
      }
    }

    console.log(`[CHECKTOKEN] Parsed as ${source}`);

    if (!refreshToken || !clientData) {
      console.log(`[ERROR]: Missing refreshToken or clientData`);
      res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
      return;
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
    decodedRefreshToken = decodedRefreshToken.replace('&reg=0', '').replace('&reg=1', '');

    let username = '';
    let passwordVal = '';

    if (decodedRefreshToken.includes('&growID=')) {
      const uMatch = decodedRefreshToken.match(/&growID=([^&]*)/);
      const pMatch = decodedRefreshToken.match(/&password=(.*)$/);
      if (uMatch) username = uMatch[1];
      if (pMatch) passwordVal = pMatch[1];
    } else if (decodedRefreshToken.includes('&growId=')) {
      const uMatch = decodedRefreshToken.match(/&growId=([^&]*)/);
      const pMatch = decodedRefreshToken.match(/&password=([^&]*)/);
      if (uMatch) username = uMatch[1];
      if (pMatch) passwordVal = pMatch[1];
    }

    let rawClient = clientData;
    try {
      const testDecoded = Buffer.from(clientData, 'base64').toString('utf-8');
      if (testDecoded.includes('platformID|') || testDecoded.includes('protocol|') || testDecoded.includes('f|')) {
        rawClient = testDecoded;
      }
    } catch {}

    if (!rawClient || rawClient.length < 5) {
      rawClient = DEFAULT_CLIENT_DATA;
    } else {
      if (!rawClient.includes('hash|')) {
        rawClient += 'hash|123456789\n';
      }
      if (!rawClient.includes('game_version|')) {
        rawClient += 'game_version|4.35\n';
      }
      if (!rawClient.includes('sid|') && !rawClient.includes('wk|')) {
        rawClient += 'sid|00000000000000000000000000000000\nwk|00000000000000000000000000000000\n';
      }
      if (!rawClient.includes('mac|')) {
        rawClient += 'mac|02:00:00:00:00:00\n';
      }
      if (!rawClient.includes('rid|')) {
        rawClient += 'rid|00000000000000000000000000000000\n';
      }
    }

    const cleanClient = rawClient.endsWith('\n') ? rawClient.slice(0, -1) : rawClient;
    const gtopiaPayload = `loginInfo=${cleanClient}&growID=${username}&password=${passwordVal}`;
    const token = Buffer.from(gtopiaPayload).toString('base64');

    res.send(
      JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
        accountAge: 2,
      }),
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
