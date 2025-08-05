#!/bin/bash

# Upgrade SignedVault script
echo "🔄 Starting SignedVault upgrade..."

# Source environment variables
echo "📋 Loading environment variables..."
source .env

# Check if required environment variables are set
if [ -z "$PRIVATE_KEY" ]; then
    echo "❌ Error: PRIVATE_KEY not set in .env file"
    exit 1
fi

if [ -z "$PERMIT2" ]; then
    echo "❌ Error: PERMIT2 not set in .env file"
    exit 1
fi

# Check if proxy address is provided
if [ -z "$PROXY_ADDRESS" ]; then
    echo "❌ Error: PROXY_ADDRESS not set in .env file"
    echo "💡 Please set PROXY_ADDRESS in your .env file or run: export PROXY_ADDRESS=<your_proxy_address>"
    exit 1
fi

echo "✅ Environment variables loaded successfully"
echo "📋 Upgrading proxy at: $PROXY_ADDRESS"

# Deploy new implementation
echo "🔨 Deploying new SignedVault implementation..."
forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deployImplementation()" --rpc-url $RPC_URL --broadcast --verify

# Wait 5 seconds
echo "⏳ Waiting 5 seconds for implementation deployment to be confirmed..."
sleep 5

# Get the deployed implementation address from the logs
IMPLEMENTATION_ADDRESS=$(forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deployImplementation()" --rpc-url $RPC_URL --silent | grep "SignedVault implementation deployed at:" | tail -1 | awk '{print $NF}')

if [ -z "$IMPLEMENTATION_ADDRESS" ]; then
    echo "❌ Error: Could not get implementation address"
    exit 1
fi

echo "📋 New implementation deployed at: $IMPLEMENTATION_ADDRESS"

# Upgrade proxy
echo "🔧 Upgrading SignedVault proxy..."
forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "upgrade(address,address)" $PROXY_ADDRESS $IMPLEMENTATION_ADDRESS --rpc-url $RPC_URL --broadcast --verify

# Wait 5 seconds
echo "⏳ Waiting 5 seconds for upgrade to be confirmed..."
sleep 5

echo "✅ Upgrade completed successfully!"
echo "📋 Proxy: $PROXY_ADDRESS"
echo "📋 New Implementation: $IMPLEMENTATION_ADDRESS"

# Update addresses file
echo "IMPLEMENTATION_ADDRESS=$IMPLEMENTATION_ADDRESS" > deployed_addresses.txt
echo "PROXY_ADDRESS=$PROXY_ADDRESS" >> deployed_addresses.txt
echo "UPGRADE_DATE=$(date)" >> deployed_addresses.txt

echo "📄 Updated addresses saved to deployed_addresses.txt"
