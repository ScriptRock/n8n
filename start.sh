#!/usr/bin/env zsh

# Environment variables
export N8N_HOST=n8n.local.external-risk.upguard.org
export WEBHOOK_URL=https://n8n.local.external-risk.upguard.org/
export VUE_APP_URL_BASE_API=https://n8n.local.external-risk.upguard.org
export NODE_TLS_REJECT_UNAUTHORIZED=0
export UPGUARD_API_URL=https://local.external-risk.upguard.org:1451/api/public
export N8N_SSO_SHARED_SECRET=tFaW8KJ3xP6ys2bEfR9uVdLq7NmZ5Gc4hQ8XjSv0TpA1YnDrC2Ma

# Enable debug logging
export N8N_LOG_LEVEL=debug

# Enhanced debugging flags
export N8N_DISABLE_AUDIENCE_CHECK=true  # Disable audience field verification in JWT
export N8N_FLEXIBLE_HASH_VERIFICATION=true  # Allow multiple hash algorithms for JWT
export N8N_LOG_JWT_DETAILS=true  # Log detailed JWT information

# Set up the log file with timestamp
LOG_FILE="n8n-debug-$(date +%Y%m%d-%H%M%S).log"
echo "Logging to $LOG_FILE"

# Change to the directory where this script is located
cd "$(dirname "$0")"

# DEBUGGING INFO:
# The JWT authentication debugging has been enhanced to:
# 1. Log detailed information about JWT token processing and verification
# 2. Handle tokens with 'audience' field which might be causing verification issues
# 3. Support flexible hash verification methods for debugging
# 4. Add fallback options for hash matching to support different hash algorithms
# 5. Enable detailed logging of the entire authentication process
# All of these can be toggled via environment variables above

# Run the original start command that was working before
# but with debug logging enabled
pnpm run build || { echo "Build failed, aborting start."; exit 1; }
pnpm run start
