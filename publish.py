This is not a one-time task. It is a recurring maintenance task that must be performed every time you upgrade your Prisma Cloud Compute Console (e.g., v30.00 → v30.01) or when you need to support a new runtime (e.g., Python 3.11).

If your Defender Layer version lags behind your Console version, protection may fail or connectivity issues may occur.

Here are the two automated ways to publish the layer to all your regions: Python Script (preferred for flexible automation) and Terraform (preferred for Infrastructure as Code).

Method 1: Python Automation Script
This script connects to your Prisma Cloud API, downloads the latest Defender Layer, and publishes it to all your target AWS regions automatically.

Save as: publish_layers.py


import boto3
import requests
import json
import os
import zipfile
import io

# ================= CONFIGURATION =================
PRISMA_CONSOLE_URL = "https://your-console.twistlock.com" # No trailing slash
PRISMA_USER = os.environ.get('PCC_USER')      # Export these in your terminal
PRISMA_PASS = os.environ.get('PCC_PASS')      # Export these in your terminal

# Target Regions to publish the layer to
TARGET_REGIONS = ['us-east-1', 'us-west-2', 'eu-central-1']

# Runtimes this layer supports (Prisma Universal Layer usually supports all)
COMPATIBLE_RUNTIMES = [
    'python3.8', 'python3.9', 'python3.10', 'python3.11', 'python3.12',
    'nodejs16.x', 'nodejs18.x', 'nodejs20.x'
]
# =================================================

def get_auth_token():
    url = f"{PRISMA_CONSOLE_URL}/api/v1/authenticate"
    payload = {"username": PRISMA_USER, "password": PRISMA_PASS}
    try:
        resp = requests.post(url, json=payload, verify=False) # Verify=True in production!
        resp.raise_for_status()
        return resp.json()['token']
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        exit(1)

def download_defender_layer(token):
    print("⬇️  Downloading Serverless Defender Bundle from Prisma Cloud...")
    url = f"{PRISMA_CONSOLE_URL}/api/v1/defenders/serverless/bundle"
    headers = {"Authorization": f"Bearer {token}"}
    
    # We request the AWS Lambda layer specifically
    # Note: Payload format may vary by version, standard request below:
    payload = {
        "provider": "aws", 
        "runtime": "python3.9" # Download the universal/compatible bundle
    }
    
    try:
        resp = requests.post(url, headers=headers, json=payload, stream=True, verify=False)
        resp.raise_for_status()
        
        # The API returns a bundle.zip which CONTAINS the layer.zip
        # We need to extract 'twistlock_defender_layer.zip' from it
        with zipfile.ZipFile(io.BytesIO(resp.content)) as bundle:
            # List files to find the layer zip
            for filename in bundle.namelist():
                if "twistlock_defender_layer.zip" in filename:
                    return bundle.read(filename)
            
            print("❌ Could not find 'twistlock_defender_layer.zip' inside the bundle.")
            print(f"Contents: {bundle.namelist()}")
            exit(1)
            
    except Exception as e:
        print(f"❌ Download Failed: {e}")
        exit(1)

def publish_to_aws(layer_content, regions):
    print("🚀 Starting AWS Layer Publication...")
    
    for region in regions:
        print(f"   --- Publishing to {region} ---")
        client = boto3.client('lambda', region_name=region)
        
        try:
            response = client.publish_layer_version(
                LayerName='twistlock-defender',
                Description='Prisma Cloud Serverless Defender',
                Content={'ZipFile': layer_content},
                CompatibleRuntimes=COMPATIBLE_RUNTIMES,
                LicenseInfo='Palo Alto Networks'
            )
            
            layer_arn = response['LayerVersionArn']
            version = response['Version']
            print(f"   ✅ Success! ARN: {layer_arn} (v{version})")
            
        except Exception as e:
            print(f"   ❌ Failed in {region}: {e}")

def main():
    if not PRISMA_USER or not PRISMA_PASS:
        print("⚠️  Please set PCC_USER and PCC_PASS environment variables.")
        return

    # 1. Get Token
    token = get_auth_token()
    
    # 2. Download the binary content of the layer
    layer_zip_bytes = download_defender_layer(token)
    
    # 3. Publish to all regions
    publish_to_aws(layer_zip_bytes, TARGET_REGIONS)

if __name__ == '__main__':
    main()
