import express from 'express';
import cors from 'cors';
import Stripe from 'stripe';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || '';

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2024-04-10' as any });

// In-memory stores (replace with a database in production)
const licenseStore = new Map<string, { email: string; plan: string; createdAt: Date }>();
const reportStore: Array<{
    licenseKey: string;
    extensionId: string;
    riskScore: number;
    findings: string[];
    reportedAt: Date;
}> = [];

// Middleware
app.use(cors());

// Raw body parser for Stripe webhooks (must come before express.json)
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    const sig = req.headers['stripe-signature'] as string;

    let event: Stripe.Event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err: any) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object as Stripe.Checkout.Session;
        const email = session.customer_email || session.customer_details?.email || 'unknown';
        const licenseKey = uuidv4();

        licenseStore.set(licenseKey, {
            email,
            plan: 'team',
            createdAt: new Date()
        });

        console.log(`License created: ${licenseKey} for ${email}`);
    }

    res.json({ received: true });
});

// JSON body parser for all other routes
app.use(express.json());

// POST /api/checkout: create a Stripe Checkout session
app.post('/api/checkout', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            customer_email: email,
            line_items: [
                {
                    price: STRIPE_PRICE_ID,
                    quantity: 1
                }
            ],
            mode: 'subscription',
            success_url: 'https://extguard.dev/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'https://extguard.dev/cancel'
        });

        res.json({ url: session.url });
    } catch (err: any) {
        console.error('Checkout error:', err.message);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// POST /api/validate: validate a license key and return a signed JWT
app.post('/api/validate', (req, res) => {
    const { licenseKey } = req.body;
    if (!licenseKey) {
        return res.status(400).json({ error: 'licenseKey is required' });
    }

    const license = licenseStore.get(licenseKey);
    if (!license) {
        return res.json({ valid: false });
    }

    const token = jwt.sign(
        {
            licenseKey,
            email: license.email,
            plan: license.plan
        },
        JWT_SECRET,
        { expiresIn: '365d' }
    );

    res.json({ valid: true, jwt: token });
});

// POST /api/report: accept scan report from an extension
app.post('/api/report', (req, res) => {
    const { licenseKey, extensionId, riskScore, findings } = req.body;

    if (!licenseKey || !extensionId) {
        return res.status(400).json({ error: 'licenseKey and extensionId are required' });
    }

    const license = licenseStore.get(licenseKey);
    if (!license) {
        return res.status(401).json({ error: 'Invalid license key' });
    }

    reportStore.push({
        licenseKey,
        extensionId,
        riskScore: riskScore || 0,
        findings: findings || [],
        reportedAt: new Date()
    });

    res.json({ success: true });
});

// GET /api/reports/:licenseKey: get all reports for a license
app.get('/api/reports/:licenseKey', (req, res) => {
    const { licenseKey } = req.params;

    const license = licenseStore.get(licenseKey);
    if (!license) {
        return res.status(401).json({ error: 'Invalid license key' });
    }

    const reports = reportStore.filter(r => r.licenseKey === licenseKey);
    res.json({ reports });
});

// GET /health
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`ExtGuard backend running on port ${PORT}`);
});

export default app;
