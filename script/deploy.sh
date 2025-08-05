#!/bin/bash

# Deploy SignedVault script
echo "🚀 Starting SignedVault deployment..."

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

echo "✅ Environment variables loaded successfully"

# Deploy implementation
echo "🔨 Deploying SignedVault implementation..."
forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deployImplementation()" --rpc-url $RPC_URL --broadcast --verify

# Wait 5 seconds
echo "⏳ Waiting 5 seconds for implementation deployment to be confirmed..."
sleep 5

# Get the deployed implementation address from the logs
# This assumes the implementation address is the last deployed contract
IMPLEMENTATION_ADDRESS=$(forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deployImplementation()" --rpc-url $RPC_URL --silent | grep "SignedVault implementation deployed at:" | tail -1 | awk '{print $NF}')

if [ -z "$IMPLEMENTATION_ADDRESS" ]; then
    echo "❌ Error: Could not get implementation address"
    exit 1
fi

echo "📋 Implementation deployed at: $IMPLEMENTATION_ADDRESS"

# Deploy proxy
echo "🔧 Deploying SignedVault proxy..."
forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deploy(address)" $IMPLEMENTATION_ADDRESS --rpc-url $RPC_URL --broadcast --verify

# Wait 5 seconds
echo "⏳ Waiting 5 seconds for proxy deployment to be confirmed..."
sleep 5

# Get the deployed proxy address
PROXY_ADDRESS=$(forge script script/DeploySignedVault.s.sol:DeploySignedVault --sig "deploy(address)" $IMPLEMENTATION_ADDRESS --rpc-url $RPC_URL --silent | grep "SignedVault proxy deployed at:" | tail -1 | awk '{print $NF}')

if [ -z "$PROXY_ADDRESS" ]; then
    echo "❌ Error: Could not get proxy address"
    exit 1
fi

echo "✅ Deployment completed successfully!"
echo "📋 Implementation: $IMPLEMENTATION_ADDRESS"
echo "📋 Proxy: $PROXY_ADDRESS"

# Save addresses to a file for future reference
echo "IMPLEMENTATION_ADDRESS=$IMPLEMENTATION_ADDRESS" > deployed_addresses.txt
echo "PROXY_ADDRESS=$PROXY_ADDRESS" >> deployed_addresses.txt
echo "DEPLOYMENT_DATE=$(date)" >> deployed_addresses.txt

echo "📄 Addresses saved to deployed_addresses.txt" 
