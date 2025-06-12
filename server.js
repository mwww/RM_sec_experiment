const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
require('dotenv').config();

const { initDatabase } = require('./config/database');
const logger = require('./utils/logger');

// Import routes
const v1AuthRoutes = require('./routes/v1/auth');
const v1UserRoutes = require('./routes/v1/users');
const v1DataRoutes = require('./routes/v1/data');

const v2AuthRoutes = require('./routes/v2/auth');
const v2UserRoutes = require('./routes/v2/users');
const v2DataRoutes = require('./routes/v2/data');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
initDatabase();

// Basic middleware
app.use(express.json());
app.use(morgan('combined'));

// V1 Routes (Insecure) - Permissive CORS and no security headers
app.use(
  '/v1',
  cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['*'],
  })
);

// V2 Routes (Secure) - Restricted CORS and security headers
app.use('/v2', helmet());
app.use(
  '/v2',
  cors({
    origin: ['http://localhost:3000', 'https://yourdomain.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// API Routes
// V1 - Insecure routes
app.use('/v1/auth', v1AuthRoutes);
app.use('/v1/users', v1UserRoutes);
app.use('/v1/data', v1DataRoutes);

// V2 - Secure routes
app.use('/v2/auth', v2AuthRoutes);
app.use('/v2/users', v2UserRoutes);
app.use('/v2/data', v2DataRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

// Error handling
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 V1 (Insecure): http://localhost:${PORT}/v1`);
  console.log(`🔒 V2 (Secure): http://localhost:${PORT}/v2`);
});
