#!/bin/bash
# VM Cron Setup Example
#
# This script demonstrates how to set up Vuln Tower as a cron job
# on a VM or bare-metal server.

set -e

# Configuration
PROJECT_DIR="/opt/vuln-tower"
VENV_DIR="$PROJECT_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python"
LOG_DIR="/var/log/vuln-tower"
DB_DIR="/var/lib/vuln-tower"

echo "Setting up Vuln Tower for cron execution..."

# Create directories
sudo mkdir -p "$PROJECT_DIR"
sudo mkdir -p "$LOG_DIR"
sudo mkdir -p "$DB_DIR"
sudo chown $USER:$USER "$LOG_DIR" "$DB_DIR"

# Clone or copy project
if [ ! -d "$PROJECT_DIR/vuln_tower" ]; then
    echo "Please copy the vuln_tower directory to $PROJECT_DIR"
    exit 1
fi

cd "$PROJECT_DIR"

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

# Install dependencies
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r requirements.txt

# Create environment file
ENV_FILE="$PROJECT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" << 'EOF'
# Vuln Tower Configuration
# Edit this file with your actual values

# General Configuration
export APP_NAME="vuln-tower"
export LOG_LEVEL="INFO"
export RUN_MODE="cron"

# Database Configuration
export DB_TYPE="sqlite"
export DB_NAME="/var/lib/vuln-tower/vuln_tower.db"

# NVD Configuration
export NVD_API_KEY=""
export FETCH_WINDOW_MINUTES="60"
export MAX_RESULTS_PER_RUN="100"
export REQUEST_TIMEOUT="30"

# Filter Configuration
export MIN_CVSS_SCORE="7.0"
export KEYWORDS=""
export PRODUCTS=""
export VENDORS=""
export ATTACK_VECTOR=""

# Notification Configuration
export ENABLE_DISCORD="false"
export DISCORD_WEBHOOK_URL=""
export ENABLE_SLACK="false"
export SLACK_WEBHOOK_URL=""
export ENABLE_TEAMS="false"
export TEAMS_WEBHOOK_URL=""
export ENABLE_TELEGRAM="false"
export TELEGRAM_BOT_TOKEN=""
export TELEGRAM_CHAT_ID=""

# Pipeline Configuration (optional)
export ENABLE_PIPELINE="false"
export PIPELINE_STEPS=""
export LLM_PROVIDER="openai"
export LLM_API_KEY=""
export LLM_MODEL="gpt-4o-mini"
EOF
    
    echo "Created environment file at $ENV_FILE"
    echo "Please edit it with your configuration values"
    chmod 600 "$ENV_FILE"
fi

# Create runner script
RUNNER_SCRIPT="$PROJECT_DIR/run.sh"
cat > "$RUNNER_SCRIPT" << EOF
#!/bin/bash
# Vuln Tower Runner Script

set -e

# Load environment variables
source "$ENV_FILE"

# Run Vuln Tower
cd "$PROJECT_DIR"
"$PYTHON_BIN" -m vuln_tower.main >> "$LOG_DIR/vuln-tower.log" 2>&1

# Rotate logs if they get too large (keep last 10MB)
LOG_FILE="$LOG_DIR/vuln-tower.log"
if [ -f "\$LOG_FILE" ] && [ \$(stat -f%z "\$LOG_FILE" 2>/dev/null || stat -c%s "\$LOG_FILE") -gt 10485760 ]; then
    mv "\$LOG_FILE" "\$LOG_FILE.old"
    touch "\$LOG_FILE"
fi
EOF

chmod +x "$RUNNER_SCRIPT"

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit configuration: $ENV_FILE"
echo "2. Test the runner: $RUNNER_SCRIPT"
echo "3. Add to crontab:"
echo ""
echo "   # Run Vuln Tower every hour"
echo "   0 * * * * $RUNNER_SCRIPT"
echo ""
echo "To install crontab entry:"
echo "   (crontab -l 2>/dev/null; echo '0 * * * * $RUNNER_SCRIPT') | crontab -"
echo ""
echo "View logs: tail -f $LOG_DIR/vuln-tower.log"
