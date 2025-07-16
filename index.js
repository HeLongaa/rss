require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const RSSParser = require('rss-parser');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const cors = require('cors');

const app = express();
const parser = new RSSParser();

// Print environment variables (excluding secrets)
console.log('Environment Check:', {
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    GITHUB_CALLBACK_URL: process.env.GITHUB_CALLBACK_URL,
    ALLOWED_GITHUB_USERNAME: process.env.ALLOWED_GITHUB_USERNAME,
    CLIENT_ID_SET: !!process.env.GITHUB_CLIENT_ID,
    CLIENT_SECRET_SET: !!process.env.GITHUB_CLIENT_SECRET
});

// Middleware
app.use(cors({
    origin: 'http://localhost:4321', // 允许来自 Astro 开发服务器的请求
    credentials: true // 允许跨域请求携带凭证
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Debug middleware
app.use((req, res, next) => {
    console.log('Request URL:', req.url);
    console.log('Is Authenticated:', req.isAuthenticated());
    console.log('User:', req.user);
    next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Passport configuration
console.log('OAuth Configuration:', {
    clientID: process.env.GITHUB_CLIENT_ID ? 'Set' : 'Not Set',
    clientSecret: process.env.GITHUB_CLIENT_SECRET ? 'Set' : 'Not Set',
    callbackURL: process.env.GITHUB_CALLBACK_URL
});

// Configure GitHub strategy with detailed error handling
const githubOptions = {
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: ['user:email'],
    // Add custom request options
    customHeaders: {
        "User-Agent": "Node.js"
    }
};

console.log('GitHub Strategy Options:', {
    ...githubOptions,
    clientSecret: '[HIDDEN]'
});

passport.use(new GitHubStrategy(githubOptions,
    function (accessToken, refreshToken, profile, done) {
        console.log('GitHub Auth Callback:', {
            profileId: profile.id,
            username: profile.username,
            displayName: profile.displayName
        });

        if (profile.username === process.env.ALLOWED_GITHUB_USERNAME) {
            return done(null, profile);
        }
        return done(null, false);
    }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
};

// RSS feeds file path
const RSS_FEEDS_FILE = path.join(__dirname, 'rss_feeds.json');
const RSS_DATA_FILE = path.join(__dirname, 'rss.json');

// Initialize RSS feeds file if it doesn't exist
async function initializeRSSFeeds() {
    try {
        await fs.access(RSS_FEEDS_FILE);
    } catch {
        await fs.writeFile(RSS_FEEDS_FILE, JSON.stringify([], null, 2));
    }
}

// Authentication routes
app.get('/auth/github',
    (req, res, next) => {
        console.log('Starting GitHub authentication...');
        console.log('Session:', req.session);
        next();
    },
    passport.authenticate('github')
);

app.get('/auth/github/callback',
    (req, res, next) => {
        passport.authenticate('github', (err, user, info) => {
            if (err) {
                console.error('Authentication Error:', err);
                return res.redirect('/');
            }

            if (!user) {
                console.log('Authentication Failed');
                return res.redirect('/');
            }

            req.logIn(user, (err) => {
                if (err) {
                    console.error('Login Error:', err);
                    return res.redirect('/');
                }
                return res.redirect('/');
            });
        })(req, res, next);
    }
);

// Add login page route
app.get('/login', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RSS Service - Login</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                .footer {
                    position: fixed;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    padding: 1rem;
                    margin: 2rem;
                }
            </style>
        </head>
        <body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center p-4">
            <div class="bg-white rounded-lg shadow-2xl max-w-md w-full p-8 space-y-6">
                <div class="text-center">
                    <i class="fas fa-rss text-5xl text-blue-500 mb-4"></i>
                    <h1 class="text-3xl font-bold text-gray-800">RSS Service</h1>
                </div>
                
                <div class="space-y-4">
                    <p class="text-gray-600 text-center">Please try again</p>
                    <a href="/" class="block w-full bg-gray-800 hover:bg-gray-700 text-white font-semibold py-3 px-4 rounded-lg text-center transition duration-300 ease-in-out transform hover:scale-105">
                        <i class="fas fa-home mr-2"></i>
                        Return to Home
                    </a>
                </div>
            </div>

            <!-- Footer -->
            <div class="footer">
                <div class="bg-white rounded-lg shadow-lg p-4 max-w-xs mx-auto text-center">
                    <p class="text-gray-600">
                        <span class="font-medium">Deployed by</span>
                        <i class="fas fa-heart text-red-500 mx-1"></i>
                        <span class="font-medium">RSS Service</span>
                    </p>
                </div>
            </div>
        </body>
        </html>
    `);
});

// API Routes
app.post('/api/feeds', isAuthenticated, async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Validate RSS feed
        try {
            await parser.parseURL(url);
        } catch (error) {
            return res.status(400).json({ error: 'Invalid RSS feed' });
        }

        // Read existing feeds
        const feeds = JSON.parse(await fs.readFile(RSS_FEEDS_FILE, 'utf8'));

        // Check if feed already exists
        if (feeds.includes(url)) {
            return res.status(400).json({ error: 'Feed already exists' });
        }

        // Add new feed
        feeds.push(url);
        await fs.writeFile(RSS_FEEDS_FILE, JSON.stringify(feeds, null, 2));

        // Update RSS data immediately after adding new feed
        await updateRSSData();

        res.json({ message: 'Feed added successfully' });
    } catch (error) {
        console.error('Error adding feed:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/feeds', isAuthenticated, async (req, res) => {
    try {
        const feeds = JSON.parse(await fs.readFile(RSS_FEEDS_FILE, 'utf8'));
        res.json(feeds);
    } catch (error) {
        console.error('Error getting feeds:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add delete feed endpoint
app.delete('/api/feeds', isAuthenticated, async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        const feeds = JSON.parse(await fs.readFile(RSS_FEEDS_FILE, 'utf8'));
        const index = feeds.indexOf(url);

        if (index === -1) {
            return res.status(404).json({ error: 'Feed not found' });
        }

        feeds.splice(index, 1);
        await fs.writeFile(RSS_FEEDS_FILE, JSON.stringify(feeds, null, 2));
        res.json({ message: 'Feed deleted successfully' });
    } catch (error) {
        console.error('Error deleting feed:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add logout endpoint
app.post('/auth/logout', (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.error('Error logging out:', err);
            return res.status(500).json({ error: 'Error logging out' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// Add endpoint to get RSS data
app.get('/api/rss', async (req, res) => {
    try {
        const rssData = JSON.parse(await fs.readFile(RSS_DATA_FILE, 'utf8'));
        res.json(rssData);
    } catch (error) {
        console.error('Error getting RSS data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Function to update RSS data
async function updateRSSData() {
    try {
        console.log('Starting RSS data update...');
        const feeds = JSON.parse(await fs.readFile(RSS_FEEDS_FILE, 'utf8'));
        const allItems = [];
        const updateErrors = [];

        for (const feedUrl of feeds) {
            try {
                console.log(`Fetching RSS feed: ${feedUrl}`);
                const feed = await parser.parseURL(feedUrl);
                const items = feed.items.map(item => ({
                    title: item.title,
                    author: item.creator || item.author || feed.title || 'Unknown',
                    date: item.isoDate || item.pubDate || new Date().toISOString(),
                    link: item.link,
                    content: item.contentSnippet || item.content || ''
                }));
                allItems.push(...items);
                console.log(`Successfully fetched ${items.length} items from ${feedUrl}`);
            } catch (error) {
                console.error(`Error parsing feed ${feedUrl}:`, error);
                updateErrors.push({ url: feedUrl, error: error.message });
            }
        }

        // Sort by date (newest first) and limit to recent items
        allItems.sort((a, b) => new Date(b.date) - new Date(a.date));

        // Write to RSS data file
        await fs.writeFile(RSS_DATA_FILE, JSON.stringify(allItems, null, 2));
        console.log(`RSS data update completed. Total items: ${allItems.length}`);

        // If there were any errors, log them
        if (updateErrors.length > 0) {
            console.error('RSS update errors:', updateErrors);
        }

        return { success: true, itemCount: allItems.length, errors: updateErrors };
    } catch (error) {
        console.error('Error updating RSS data:', error);
        return { success: false, error: error.message };
    }
}

// Schedule RSS updates
let updateInterval = 30 * 60 * 1000; // 30 minutes by default
let updateTimer = null;

function scheduleRSSUpdates(interval = 30 * 60 * 1000) {
    // Clear existing timer if any
    if (updateTimer) {
        clearInterval(updateTimer);
    }

    // Set new interval
    updateInterval = interval;
    updateTimer = setInterval(async () => {
        console.log(`Scheduled RSS update starting... (Interval: ${interval / 60000} minutes)`);
        await updateRSSData();
    }, interval);

    console.log(`RSS updates scheduled every ${interval / 60000} minutes`);
}

// Add endpoint to manually trigger RSS update
app.post('/api/refresh', isAuthenticated, async (req, res) => {
    try {
        const result = await updateRSSData();
        if (result.success) {
            res.json({ message: 'RSS data updated successfully', ...result });
        } else {
            res.status(500).json({ error: 'Failed to update RSS data', ...result });
        }
    } catch (error) {
        console.error('Error refreshing RSS data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add endpoint to change update interval
app.post('/api/update-interval', isAuthenticated, (req, res) => {
    const { interval } = req.body; // interval in minutes
    if (!interval || interval < 1) {
        return res.status(400).json({ error: 'Invalid interval' });
    }

    const intervalMs = interval * 60 * 1000;
    scheduleRSSUpdates(intervalMs);
    res.json({ message: `Update interval set to ${interval} minutes` });
});

// Initialize and start server
async function startServer() {
    await initializeRSSFeeds();
    await updateRSSData(); // Initial update
    scheduleRSSUpdates(); // Start scheduled updates

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

startServer(); 