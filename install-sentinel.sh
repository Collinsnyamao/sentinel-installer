#!/bin/bash
# install-sentinel.sh - Script to install and set up the Sentinel VPS (without MongoDB installation)

# Exit on any error
set -e

# Set colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Sentinel VPS Installation Script ===${NC}"
echo "This script will install and configure the Sentinel VPS application."
echo -e "${YELLOW}Note: This script will not install MongoDB. You need to have MongoDB already running.${NC}"

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
APP_DIR="/opt/sentinel-vps"
echo -e "\n${YELLOW}Creating application directory at ${APP_DIR}...${NC}"
mkdir -p $APP_DIR
mkdir -p $APP_DIR/logs
mkdir -p $APP_DIR/ssl

# Ask for domain name
read -p "Enter your domain name (leave blank for localhost): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    DOMAIN_NAME="localhost"
    echo "Using 'localhost' as domain"
fi

# Ask for MongoDB connection details
echo -e "\n${YELLOW}MongoDB Connection Configuration${NC}"
read -p "MongoDB Host (default: localhost): " MONGO_HOST
MONGO_HOST=${MONGO_HOST:-localhost}

read -p "MongoDB Port (default: 27017): " MONGO_PORT
MONGO_PORT=${MONGO_PORT:-27017}

read -p "MongoDB Database Name (default: sentinel): " MONGO_DB
MONGO_DB=${MONGO_DB:-sentinel}

read -p "MongoDB Username (leave blank if not required): " MONGO_USER
read -s -p "MongoDB Password (leave blank if not required): " MONGO_PASS
echo ""

# Construct MongoDB URI
if [ -z "$MONGO_USER" ]; then
    MONGO_URI="mongodb://${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}"
else
    MONGO_URI="mongodb://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}"
fi

echo -e "${GREEN}MongoDB URI configured${NC}"

# Ask for JWT secret
read -p "Enter a JWT secret (leave blank to generate one): " JWT_SECRET
if [ -z "$JWT_SECRET" ]; then
    JWT_SECRET=$(openssl rand -base64 32)
    echo "Generated JWT secret: $JWT_SECRET"
fi

# Ask for Node secret
read -p "Enter a Node secret for worker authentication (leave blank to generate one): " NODE_SECRET
if [ -z "$NODE_SECRET" ]; then
    NODE_SECRET=$(openssl rand -base64 32)
    echo "Generated Node secret: $NODE_SECRET"
fi

# Create .env file
echo -e "\n${YELLOW}Creating .env file...${NC}"
cat > $APP_DIR/.env << EOF
NODE_ENV=production
PORT=3000
MONGODB_URI=${MONGO_URI}
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRES_IN=1d
NODE_SECRET=${NODE_SECRET}
LOG_LEVEL=info
LOG_MAX_FILES=14d
LOG_DIRECTORY=${APP_DIR}/logs
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
WS_HEARTBEAT_INTERVAL=30000
WS_HEARTBEAT_TIMEOUT=60000
EOF

# Create self-signed SSL certificate if needed
if [[ "$DOMAIN_NAME" != "localhost" ]]; then
    echo -e "\n${YELLOW}Creating self-signed SSL certificate...${NC}"
    echo -e "${YELLOW}Note: For production, replace these with proper certificates from Let's Encrypt${NC}"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $APP_DIR/ssl/privkey.pem \
        -out $APP_DIR/ssl/cert.pem \
        -subj "/CN=$DOMAIN_NAME" \
        -addext "subjectAltName = DNS:$DOMAIN_NAME"
    
    # Create chain.pem as a copy of cert.pem for simplicity
    cp $APP_DIR/ssl/cert.pem $APP_DIR/ssl/chain.pem
else
    echo -e "\n${YELLOW}Skipping SSL certificate creation for localhost${NC}"
fi

# Clone the application from repository or copy files
echo -e "\n${YELLOW}How would you like to install the application?${NC}"
echo "1. Clone from Git repository"
echo "2. Use local files (current directory)"
read -p "Select an option (1/2): " INSTALL_OPTION

if [ "$INSTALL_OPTION" == "1" ]; then
    read -p "Enter Git repository URL: " REPO_URL
    git clone $REPO_URL $APP_DIR/app
    cd $APP_DIR/app
elif [ "$INSTALL_OPTION" == "2" ]; then
    # Assuming the script is run from the directory containing the app files
    echo -e "\n${YELLOW}Copying local files to $APP_DIR/app...${NC}"
    mkdir -p $APP_DIR/app
    cp -r ./* $APP_DIR/app/
    cd $APP_DIR/app
else
    echo -e "${RED}Invalid option. Exiting.${NC}"
    exit 1
fi

# Install dependencies
echo -e "\n${YELLOW}Installing application dependencies...${NC}"
npm install --production

# Test MongoDB connection
echo -e "\n${YELLOW}Testing MongoDB connection...${NC}"
cat > $APP_DIR/test-mongo.js << EOF
const mongoose = require('mongoose');

mongoose.connect('${MONGO_URI}', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('MongoDB connection successful');
  process.exit(0);
})
.catch(err => {
  console.error('MongoDB connection error:', err.message);
  process.exit(1);
});
EOF

if node $APP_DIR/test-mongo.js; then
    echo -e "${GREEN}MongoDB connection successful${NC}"
else
    echo -e "${RED}Failed to connect to MongoDB. Please check your connection details and ensure MongoDB is running.${NC}"
    echo -e "${YELLOW}You may need to fix the MongoDB URI in $APP_DIR/.env before continuing.${NC}"
    read -p "Do you want to continue with the installation? (y/n): " CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        echo "Installation aborted."
        exit 1
    fi
fi

# Remove test file
rm $APP_DIR/test-mongo.js

# Set up PM2 ecosystem file
echo -e "\n${YELLOW}Setting up PM2 configuration...${NC}"
cat > $APP_DIR/ecosystem.config.js << EOF
module.exports = {
  apps: [
    {
      name: 'sentinel-vps',
      script: '$APP_DIR/app/server.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        MONGODB_URI: '${MONGO_URI}',
        JWT_SECRET: '${JWT_SECRET}',
        NODE_SECRET: '${NODE_SECRET}',
        LOG_LEVEL: 'info',
        LOG_DIRECTORY: '${APP_DIR}/logs',
        SSL_PATH: '${APP_DIR}/ssl'
      }
    }
  ]
};
EOF

# Create initial admin user
echo -e "\n${YELLOW}Creating initial admin user...${NC}"
read -p "Enter admin username: " ADMIN_USER
read -s -p "Enter admin password: " ADMIN_PASS
echo ""
read -p "Enter admin email: " ADMIN_EMAIL

# Create a script to create the admin user
cat > $APP_DIR/create-admin.js << EOF
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Connect to MongoDB
mongoose.connect('${MONGO_URI}', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Define User schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  role: String,
  active: Boolean,
  createdAt: Date
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

const User = mongoose.model('User', userSchema);

// Create admin user
async function createAdminUser() {
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ username: '${ADMIN_USER}' });
    
    if (existingUser) {
      console.log('Admin user already exists.');
      mongoose.connection.close();
      process.exit(0);
    }
    
    // Create new admin user
    const adminUser = new User({
      username: '${ADMIN_USER}',
      password: '${ADMIN_PASS}',
      email: '${ADMIN_EMAIL}',
      role: 'admin',
      active: true,
      createdAt: new Date()
    });
    
    await adminUser.save();
    console.log('Admin user created successfully.');
    
    mongoose.connection.close();
    process.exit(0);
  } catch (error) {
    console.error('Error creating admin user:', error);
    mongoose.connection.close();
    process.exit(1);
  }
}

createAdminUser();
EOF

# Run the admin user creation script
node $APP_DIR/create-admin.js

# Remove the script after use
rm $APP_DIR/create-admin.js

# Set proper permissions
echo -e "\n${YELLOW}Setting proper permissions...${NC}"
chown -R $(whoami):$(whoami) $APP_DIR
chmod -R 755 $APP_DIR

# Create a systemd service for PM2
echo -e "\n${YELLOW}Creating systemd service for PM2...${NC}"
pm2 startup systemd
pm2 start $APP_DIR/ecosystem.config.js
pm2 save

# Set up firewall if UFW is available
if command -v ufw &> /dev/null; then
    echo -e "\n${YELLOW}Setting up firewall rules...${NC}"
    ufw allow ssh
    ufw allow 3000/tcp
    
    # Ask if user wants to set up a reverse proxy
    read -p "Do you want to set up a reverse proxy with Nginx? (y/n): " SETUP_NGINX
    if [ "$SETUP_NGINX" == "y" ] || [ "$SETUP_NGINX" == "Y" ]; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        
        # Install Nginx
        apt-get install -y nginx
        
        # Create Nginx configuration
        cat > /etc/nginx/sites-available/sentinel << EOF
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${DOMAIN_NAME};
    
    ssl_certificate ${APP_DIR}/ssl/cert.pem;
    ssl_certificate_key ${APP_DIR}/ssl/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
        
        # Enable the site
        ln -s /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
        
        # Test Nginx configuration
        nginx -t
        
        # Restart Nginx
        systemctl restart nginx
        
        echo -e "${GREEN}Nginx reverse proxy set up successfully!${NC}"
        echo -e "${YELLOW}Note: For production, replace the self-signed certificates with Let's Encrypt certificates${NC}"
    else
        echo -e "${YELLOW}Skipping Nginx setup...${NC}"
    fi
    
    # Enable the firewall
    ufw --force enable
    echo -e "${GREEN}Firewall configured!${NC}"
fi

echo -e "\n${GREEN}Sentinel VPS installation complete!${NC}"
echo -e "${GREEN}Your Sentinel VPS is running at: http://localhost:3000${NC}"
if [[ "$DOMAIN_NAME" != "localhost" ]]; then
    echo -e "${GREEN}Or access via domain: https://${DOMAIN_NAME}${NC}"
fi
echo -e "\n${YELLOW}Admin login credentials:${NC}"
echo -e "Username: ${ADMIN_USER}"
echo -e "Password: (as provided during installation)"
echo -e "\n${YELLOW}Important:${NC}"
echo -e "1. Make sure to securely store the JWT_SECRET and NODE_SECRET"
echo -e "2. For production, replace self-signed certificates with proper ones"
echo -e "3. Configure regular backups of the MongoDB database"

# Generate a token for worker nodes
echo -e "\n${YELLOW}Here's the Node Secret for your worker VPS nodes:${NC}"
echo "$NODE_SECRET"
echo -e "Use this value for the NODE_SECRET environment variable on worker nodes"

exit 0