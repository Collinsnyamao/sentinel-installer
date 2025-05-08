#!/bin/bash
# install-worker.sh - Script to install and set up a Worker Node

# Exit on any error
set -e

# Set colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Worker Node Installation Script ===${NC}"
echo "This script will install and configure a Worker Node for the Sentinel VPS network."

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Update system packages
echo -e "\n${YELLOW}Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
apt-get install -y curl wget git build-essential

# Install Node.js if not already installed
if ! command -v node &> /dev/null; then
    echo -e "\n${YELLOW}Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

# Check Node.js version
NODE_VERSION=$(node -v)
echo -e "${GREEN}Node.js installed: ${NODE_VERSION}${NC}"

# Install PM2 globally
echo -e "\n${YELLOW}Installing PM2...${NC}"
npm install pm2 -g

# Create application directory
APP_DIR="/opt/worker-node"
echo -e "\n${YELLOW}Creating application directory at ${APP_DIR}...${NC}"
mkdir -p $APP_DIR
mkdir -p $APP_DIR/logs

# Generate a unique node ID
NODE_ID="worker-$(openssl rand -hex 4)"
echo -e "${GREEN}Generated Node ID: ${NODE_ID}${NC}"

# Get Sentinel VPS details
read -p "Enter Sentinel VPS hostname or IP: " SENTINEL_HOST
read -p "Enter Sentinel VPS WebSocket port (default: 3000): " SENTINEL_PORT
SENTINEL_PORT=${SENTINEL_PORT:-3000}

# Determine protocol (ws or wss)
read -p "Does the Sentinel VPS use SSL/TLS? (y/n, default: y): " USE_SSL
USE_SSL=${USE_SSL:-y}

if [ "$USE_SSL" == "y" ] || [ "$USE_SSL" == "Y" ]; then
    WS_PROTOCOL="wss"
else
    WS_PROTOCOL="ws"
fi

# Get the authentication secret
read -p "Enter the Node Secret from the Sentinel VPS: " NODE_SECRET

# Create the worker agent file
echo -e "\n${YELLOW}Creating worker agent file...${NC}"
cat > $APP_DIR/worker-agent.js << 'EOF'
// worker-agent.js - Agent that runs on each worker VPS
const WebSocket = require('ws');
const os = require('os');
const { exec } = require('child_process');
const fs = require('fs');
const winston = require('winston');
const path = require('path');
const crypto = require('crypto');

// Configuration - loaded from environment variables
const CONFIG = {
  nodeId: process.env.NODE_ID,
  name: process.env.NODE_NAME || os.hostname(),
  sentinelUrl: process.env.SENTINEL_URL,
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || '30000'), // 30 seconds
  reconnectInterval: parseInt(process.env.RECONNECT_INTERVAL || '5000'),  // 5 seconds
  logDir: process.env.LOG_DIR || './logs',
  secretKey: process.env.NODE_SECRET,  // Used for authenticating with the sentinel
  tags: process.env.NODE_TAGS ? process.env.NODE_TAGS.split(',') : []
};

// Setup logging
if (!fs.existsSync(CONFIG.logDir)) {
  fs.mkdirSync(CONFIG.logDir, { recursive: true });
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: `worker-${CONFIG.nodeId}` },
  transports: [
    new winston.transports.File({ 
      filename: path.join(CONFIG.logDir, 'error.log'), 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: path.join(CONFIG.logDir, 'combined.log') 
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ],
});

// WebSocket connection
let ws;
let reconnectTimer;
let commandHandlers = {};

// Register command handlers
function registerCommandHandler(commandType, handler) {
  commandHandlers[commandType] = handler;
}

// Default command handlers
registerCommandHandler('exec', (args) => {
  return new Promise((resolve, reject) => {
    // SECURITY WARNING: Be very careful with exec commands!
    // In production, you should strictly limit what commands can be run
    if (!args.command) return reject('No command specified');
    
    // Add safety restrictions here
    if (args.command.includes('rm -rf') || args.command.includes('mkfs')) {
      return reject('Potentially dangerous command blocked');
    }
    
    exec(args.command, (error, stdout, stderr) => {
      if (error) {
        logger.error(`Exec error: ${error.message}`);
        return reject(error.message);
      }
      resolve({ stdout, stderr });
    });
  });
});

registerCommandHandler('status', () => {
  return Promise.resolve(getSystemMetrics());
});

registerCommandHandler('restart', () => {
  logger.info('Restart command received');
  setTimeout(() => {
    process.exit(0); // Assuming you have PM2 to restart the service
  }, 1000);
  return Promise.resolve({ message: 'Restarting...' });
});

// Connect to sentinel server
function connect() {
  // Clear any existing reconnect timer
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }
  
  const wsUrl = `${CONFIG.sentinelUrl}/${CONFIG.nodeId}`;
  logger.info(`Connecting to sentinel: ${wsUrl}`);
  
  ws = new WebSocket(wsUrl, {
    headers: {
      'X-Node-Secret': CONFIG.secretKey,
      'X-Node-ID': CONFIG.nodeId
    }
  });
  
  ws.on('open', () => {
    logger.info('Connected to sentinel server');
    
    // Register with server
    sendMessage({
      type: 'register',
      nodeId: CONFIG.nodeId,
      name: CONFIG.name,
      ip: getIpAddress(),
      tags: CONFIG.tags,
      metadata: {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        hostname: os.hostname(),
        cpus: os.cpus().length
      },
      timestamp: new Date().toISOString()
    });
    
    // Send initial heartbeat
    sendHeartbeat();
  });
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      logger.debug('Received message', { type: data.type });
      
      // Handle ping from server
      if (data.type === 'ping') {
        sendMessage({
          type: 'pong',
          timestamp: data.timestamp
        });
        return;
      }
      
      // Handle commands from the sentinel
      if (data.type === 'command') {
        const { commandId, command, parameters = {} } = data;
        
        // Check if we have a handler for this command
        if (commandHandlers[command]) {
          try {
            const result = await commandHandlers[command](parameters);
            sendCommandResponse(commandId, true, result);
          } catch (err) {
            logger.error(`Error executing command: ${command}`, { error: err });
            sendCommandResponse(commandId, false, err.toString());
          }
        } else {
          logger.warn(`Unknown command received: ${command}`);
          sendCommandResponse(commandId, false, 'Unknown command');
        }
      }
    } catch (err) {
      logger.error('Error parsing message', { error: err.message });
    }
  });
  
  ws.on('error', (error) => {
    logger.error('WebSocket error', { error: error.message });
  });
  
  ws.on('close', () => {
    logger.warn('Disconnected from sentinel server');
    // Schedule reconnection
    reconnectTimer = setTimeout(connect, CONFIG.reconnectInterval);
  });
}

// Send a message to the sentinel
function sendMessage(message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(message));
      return true;
    } catch (error) {
      logger.error(`Error sending message: ${error.message}`);
      return false;
    }
  }
  return false;
}

// Get primary IP address
function getIpAddress() {
  const interfaces = os.networkInterfaces();
  
  for (const interfaceName of Object.keys(interfaces)) {
    const addresses = interfaces[interfaceName];
    
    for (const addr of addresses) {
      if (!addr.internal && addr.family === 'IPv4') {
        return addr.address;
      }
    }
  }
  
  return '127.0.0.1'; // Fallback to localhost
}

// Get system metrics
function getSystemMetrics() {
  // Calculate CPU usage (this is an approximation)
  const cpus = os.cpus();
  const cpuCount = cpus.length;
  
  // Calculate memory usage
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const memoryUsage = ((totalMem - freeMem) / totalMem) * 100;
  
  // Get load average
  const loadAvg = os.loadavg();
  
  // Get disk usage (this requires a command)
  let diskUsage = 0;
  try {
    // This is a simple approximation for Linux
    const df = require('child_process').execSync('df -k / | tail -1 | awk \'{print $5}\'').toString().trim();
    diskUsage = parseInt(df.replace('%', ''));
  } catch (error) {
    logger.warn('Failed to get disk usage', { error: error.message });
    diskUsage = 0;
  }
  
  return {
    cpuUsage: (loadAvg[0] / cpuCount) * 100, // Approximate CPU usage
    memoryUsage,
    diskUsage,
    uptime: os.uptime(),
    loadAvg,
    platform: process.platform,
    freeMem,
    totalMem,
    cpuCount
  };
}

// Send heartbeat to the sentinel
function sendHeartbeat() {
  const metrics = getSystemMetrics();
  
  sendMessage({
    type: 'heartbeat',
    nodeId: CONFIG.nodeId,
    ip: getIpAddress(),
    timestamp: new Date().toISOString(),
    ...metrics
  });
  
  // Schedule next heartbeat
  setTimeout(sendHeartbeat, CONFIG.heartbeatInterval);
}

// Send logs to the sentinel
function sendLog(level, message, metadata = {}) {
  sendMessage({
    type: 'log',
    level,
    message,
    timestamp: new Date().toISOString(),
    metadata
  });
  
  // Also log locally
  logger[level](message, metadata);
}

// Send command response back to sentinel
function sendCommandResponse(commandId, success, result) {
  sendMessage({
    type: 'command_response',
    commandId,
    success,
    result,
    timestamp: new Date().toISOString()
  });
}

// Monkey patch console methods to also send logs to sentinel
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error
};

console.log = (...args) => {
  originalConsole.log(...args);
  sendLog('info', args.join(' '));
};

console.info = (...args) => {
  originalConsole.info(...args);
  sendLog('info', args.join(' '));
};

console.warn = (...args) => {
  originalConsole.warn(...args);
  sendLog('warn', args.join(' '));
};

console.error = (...args) => {
  originalConsole.error(...args);
  sendLog('error', args.join(' '));
};

// Add custom command handlers
registerCommandHandler('free-memory', () => {
  logger.info('Running free memory command');
  return Promise.resolve({
    free: os.freemem(),
    total: os.totalmem(),
    percentage: (os.freemem() / os.totalmem() * 100).toFixed(2) + '%'
  });
});

registerCommandHandler('list-processes', () => {
  return new Promise((resolve, reject) => {
    exec('ps aux | head -10', (error, stdout, stderr) => {
      if (error) {
        return reject(error.message);
      }
      resolve({ processes: stdout.split('\n') });
    });
  });
});

// Start the agent
function start() {
  logger.info(`Starting worker agent with ID: ${CONFIG.nodeId}`);
  logger.info(`Connecting to Sentinel at: ${CONFIG.sentinelUrl}`);
  
  // Initial connection
  connect();
  
  // Handle graceful shutdown
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Shutdown handler
function shutdown() {
  logger.info('Shutting down worker agent');
  
  sendMessage({
    type: 'status',
    status: 'offline',
    timestamp: new Date().toISOString()
  });
  
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
  }
  
  // Give time for final messages to be sent
  setTimeout(() => {
    process.exit(0);
  }, 1000);
}

// Validate configuration
function validateConfig() {
  if (!CONFIG.nodeId) {
    logger.error('NODE_ID environment variable is required');
    process.exit(1);
  }
  
  if (!CONFIG.sentinelUrl) {
    logger.error('SENTINEL_URL environment variable is required');
    process.exit(1);
  }
  
  if (!CONFIG.secretKey) {
    logger.error('NODE_SECRET environment variable is required');
    process.exit(1);
  }
}

// Export API for external use if required as a module
if (require.main !== module) {
  module.exports = {
    start,
    sendLog,
    registerCommandHandler
  };
} else {
  // Run validation
  validateConfig();
  
  // Start the agent
  start();
}
EOF

# Create package.json
echo -e "\n${YELLOW}Creating package.json...${NC}"
cat > $APP_DIR/package.json << EOF
{
  "name": "worker-node",
  "version": "1.0.0",
  "description": "Worker node agent for Sentinel VPS network",
  "main": "worker-agent.js",
  "scripts": {
    "start": "node worker-agent.js"
  },
  "dependencies": {
    "ws": "^8.13.0",
    "winston": "^3.10.0"
  }
}
EOF

# Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
cd $APP_DIR
npm install --production

# Create environment file
echo -e "\n${YELLOW}Creating environment configuration...${NC}"
SENTINEL_WS_URL="${WS_PROTOCOL}://${SENTINEL_HOST}:${SENTINEL_PORT}/ws/node"

cat > $APP_DIR/.env << EOF
NODE_ID=${NODE_ID}
NODE_NAME=$(hostname)
SENTINEL_URL=${SENTINEL_WS_URL}
HEARTBEAT_INTERVAL=30000
RECONNECT_INTERVAL=5000
LOG_LEVEL=info
LOG_DIR=${APP_DIR}/logs
NODE_SECRET=${NODE_SECRET}
NODE_TAGS=worker
EOF

# Create PM2 ecosystem file
echo -e "\n${YELLOW}Creating PM2 ecosystem file...${NC}"
cat > $APP_DIR/ecosystem.config.js << EOF
module.exports = {
  apps: [
    {
      name: 'worker-node',
      script: '${APP_DIR}/worker-agent.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        NODE_ID: '${NODE_ID}',
        NODE_NAME: '$(hostname)',
        SENTINEL_URL: '${SENTINEL_WS_URL}',
        HEARTBEAT_INTERVAL: '30000',
        RECONNECT_INTERVAL: '5000',
        LOG_LEVEL: 'info',
        LOG_DIR: '${APP_DIR}/logs',
        NODE_SECRET: '${NODE_SECRET}',
        NODE_TAGS: 'worker'
      }
    }
  ]
};
EOF

# Set permissions
echo -e "\n${YELLOW}Setting proper permissions...${NC}"
chown -R $(whoami):$(whoami) $APP_DIR
chmod -R 755 $APP_DIR

# Start with PM2
echo -e "\n${YELLOW}Starting worker agent with PM2...${NC}"
cd $APP_DIR
pm2 start ecosystem.config.js
pm2 save

# Setup PM2 to start on boot
echo -e "\n${YELLOW}Setting up PM2 to start on boot...${NC}"
pm2 startup systemd

# Set up firewall if UFW is available
if command -v ufw &> /dev/null; then
    echo -e "\n${YELLOW}Setting up firewall rules...${NC}"
    ufw allow ssh
    
    # Only allow outbound connections to the Sentinel
    ufw allow out to $SENTINEL_HOST port $SENTINEL_PORT
    
    # Enable the firewall
    ufw --force enable
    echo -e "${GREEN}Firewall configured!${NC}"
fi

# Create a useful status script
echo -e "\n${YELLOW}Creating status check script...${NC}"
cat > $APP_DIR/status.sh << 'EOF'
#!/bin/bash
# Simple script to check the worker node status

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=== Worker Node Status ==="
echo ""

# Check if PM2 is running
if ! command -v pm2 &> /dev/null; then
    echo -e "${RED}PM2 not found. Is it installed?${NC}"
    exit 1
fi

# Check if worker is running in PM2
STATUS=$(pm2 info worker-node 2>/dev/null | grep status | awk '{print $4}')
if [ "$STATUS" == "online" ]; then
    echo -e "${GREEN}Worker process: RUNNING${NC}"
else
    echo -e "${RED}Worker process: NOT RUNNING${NC}"
fi

# Check logs for recent errors
echo ""
echo "=== Recent Errors (last 5) ==="
grep -i error $APP_DIR/logs/error.log | tail -5

# Check connection status
echo ""
echo "=== Connection Status ==="
LAST_LOG=$(grep -i "connected to sentinel" $APP_DIR/logs/combined.log | tail -1)
if [ -n "$LAST_LOG" ]; then
    echo -e "${GREEN}Last connection: $LAST_LOG${NC}"
else
    echo -e "${RED}No connection log found${NC}"
fi

# Show system resources
echo ""
echo "=== System Resources ==="
echo "Memory:"
free -m | head -2
echo ""
echo "Disk:"
df -h / | head -2
echo ""
echo "CPU Load:"
uptime

# Show PM2 memory usage
echo ""
echo "=== PM2 Resource Usage ==="
pm2 status
EOF

chmod +x $APP_DIR/status.sh

# Create a log viewer helper script
echo -e "\n${YELLOW}Creating log viewer script...${NC}"
cat > $APP_DIR/logs.sh << 'EOF'
#!/bin/bash
# Simple script to view worker logs

if [ "$1" == "error" ]; then
    tail -f $APP_DIR/logs/error.log
else
    tail -f $APP_DIR/logs/combined.log
fi
EOF

chmod +x $APP_DIR/logs.sh

# Create symbolic links to the scripts
ln -sf $APP_DIR/status.sh /usr/local/bin/worker-status
ln -sf $APP_DIR/logs.sh /usr/local/bin/worker-logs

echo -e "\n${GREEN}Worker Node installation complete!${NC}"
echo -e "Worker Node ID: ${NODE_ID}"
echo -e "Connected to Sentinel: ${SENTINEL_WS_URL}"
echo -e "\n${YELLOW}Commands available:${NC}"
echo -e "- worker-status  : Check the status of the worker node"
echo -e "- worker-logs    : View live logs (use 'worker-logs error' for error logs only)"
echo -e "- pm2 monit      : Monitor the worker process in real-time"
echo -e "- pm2 restart worker-node : Restart the worker process"

exit 0