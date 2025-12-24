import boto3
import requests
import json
import os
import zipfile
import io

# ================= CONFIGURATION =================
# ⚠️ UPDATE THIS URL to your actual Prisma Console (e.g., https://us-west1.cloud.twistlock.com/...)
PRISMA_CONSOLE_URL = "https://your-console.twistlock.com" 

# AUTHENTICATION (From Local Environment Variables)
ACCESS_KEY_ID = os.environ.get('PRISMA_ACCESS_KEY')
SECRET_KEY = os.environ.get('PRISMA_SECRET_KEY')

# ✅ TARGET REGION: Singapore Only
TARGET_REGIONS = ['ap-southeast-1']

# PAYLOAD: Requests Python 3.11 to get the "Universal" Linux bundle
# This works for Node.js, Python, and other runtimes on AWS Lambda.
DEFENDER_PAYLOAD = {
    "provider": "aws",
    "runtime": "python3.11" 
}

# Runtimes to enable in AWS
COMPATIBLE_RUNTIMES = [
    'python3.8', 'python3.9', 'python3.10', 'python3.11', 'python3.12', 
    'nodejs16.x', 'nodejs18.x', 'nodejs20.x'
]
# =================================================

def get_auth_token(access_key, secret_key):
    if not access_key or not secret_key:
        print("❌ Error: Missing Environment Variables.")
        print("   Please set 'PRISMA_ACCESS_KEY' and 'PRISMA_SECRET_KEY' in your terminal.")
        exit(1)

    print(f"🔐 Authenticating to {PRISMA_CONSOLE_URL}...")
    url = f"{PRISMA_CONSOLE_URL}/api/v1/authenticate"
    payload = {"username": access_key, "password": secret_key}
    
    try:
        # Verify=True is recommended. If you have SSL issues locally, set to False temporarily.
        resp = requests.post(url, json=payload, verify=True) 
        resp.raise_for_status()
        return resp.json()['token']
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        exit(1)

def download_defender_layer(token):
    print("⬇️  Downloading Serverless Defender Bundle...")
    url = f"{PRISMA_CONSOLE_URL}/api/v1/defenders/serverless/bundle"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.post(url, headers=headers, json=DEFENDER_PAYLOAD, stream=True)
        resp.raise_for_status()
        
        with zipfile.ZipFile(io.BytesIO(resp.content)) as bundle:
            # Look for the specific layer zip file inside the bundle
            for filename in bundle.namelist():
                if "twistlock_defender_layer.zip" in filename:
                    print("   ✅ Found 'twistlock_defender_layer.zip'")
                    return bundle.read(filename)
            
            print("❌ Layer zip not found inside bundle.")
            exit(1)
            
    except Exception as e:
        print(f"❌ Download Failed: {e}")
        exit(1)

def publish_to_aws(layer_content, regions):
    print("🚀 Publishing Layer to AWS...")
    
    for region in regions:
        print(f"   --- Region: {region} ---")
        # Ensure your local AWS credentials are set for this region
        client = boto3.client('lambda', region_name=region)
        
        try:
            response = client.publish_layer_version(
                LayerName='twistlock-defender',
                Description='Prisma Cloud Serverless Defender (Universal)',
                Content={'ZipFile': layer_content},
                CompatibleRuntimes=COMPATIBLE_RUNTIMES,
                LicenseInfo='Palo Alto Networks'
            )
            
            layer_arn = response['LayerVersionArn']
            print(f"   ✅ Published: {layer_arn}")
            return layer_arn
            
        except Exception as e:
            print(f"   ❌ Failed in {region}: {e}")

def main():
    # 1. Authenticate
    token = get_auth_token(ACCESS_KEY_ID, SECRET_KEY)
    
    # 2. Download
    layer_zip = download_defender_layer(token)
    
    # 3. Publish
    publish_to_aws(layer_zip, TARGET_REGIONS)

if __name__ == '__main__':
    main()
