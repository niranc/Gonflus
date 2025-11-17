# Installation Instructions

## Node.js Version Issue

If you encounter npm version compatibility issues, you have two options:

### Option 1: Update Node.js (Recommended)

Using nvm:
```bash
nvm install 18
nvm use 18
```

Or install Node.js 18+ from https://nodejs.org/

### Option 2: Use Compatible npm Version

If you must use Node.js 14, downgrade npm:
```bash
npm install -g npm@6.14.18
```

### Then Install Dependencies

```bash
cd test-app
npm install
npm start
```

## Quick Start

```bash
# Update Node.js first (if needed)
nvm install 18
nvm use 18

# Install dependencies
cd test-app
npm install

# Start server
npm start
```

The server will be available at `http://localhost:3000`

