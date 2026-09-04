import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

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

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const _token = formData._token || '';
    const growId = formData.growId || '';
    const password = formData.password || '';

    let rawClientData = '';
    try {
      rawClientData = Buffer.from(_token, 'base64').toString('utf-8');
    } catch {
      rawClientData = _token;
    }

    // GTopia C++ PlayerLoginDetail format:
    // loginInfo=<clientData>&growID=<growId>&password=<password>
    // For Guest: password is empty (e.g. loginInfo=...&growID=Guest&password=)
    // For Registered: growID and password are both present
    const gtopiaPayload = `loginInfo=${rawClientData}&growID=${growId}&password=${password}`;
    const token = Buffer.from(gtopiaPayload).toString('base64');

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

    const gtopiaPayload = `loginInfo=${rawClient}&growID=${username}&password=${passwordVal}`;
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
