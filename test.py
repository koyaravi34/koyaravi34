import boto3
import logging
from botocore.exceptions import ClientError

# =================CONFIGURATION=================

LAYER_ARNS = {
    'us-east-1': 'arn:aws:lambda:us-east-1:123456789012:layer:twistlock-defender:1',
    'us-west-2': 'arn:aws:lambda:us-west-2:123456789012:layer:twistlock-defender:1',
}

SUPPORTED_RUNTIMES = [
    'python3.8', 'python3.9', 'python3.10', 'python3.11', 'python3.12',
    'nodejs16.x', 'nodejs18.x', 'nodejs20.x'
]

# --- SAFETY THRESHOLDS ---
MAX_LAYERS = 5
MIN_MEMORY_MB = 256        # Defender agent needs overhead; 128MB is often too tight and risks OOM.
TIMEOUT_BUFFER_SEC = 30    # If function timeout is > 870s, skip it. Defender adds latency.
MAX_TIMEOUT_SEC = 900      # AWS Hard limit (15 mins)

DRY_RUN = False            # Set True to audit without changes

# ===============================================

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_lambda_client(region):
    return boto3.client('lambda', region_name=region)

def is_protected(function_config):
    """Checks if Twistlock/Prisma layer or env vars are already present."""
    layers = function_config.get('Layers', [])
    for layer in layers:
        if 'twistlock' in layer['Arn'] or 'prisma' in layer['Arn']:
            return True
    
    env_vars = function_config.get('Environment', {}).get('Variables', {})
    if 'TW_POLICY' in env_vars:
        return True
    return False

def assess_risk(function_config):
    """
    Performs deep inspection of hardware/software constraints.
    Returns: (Boolean is_safe, String reason)
    """
    func_name = function_config['FunctionName']
    
    # 1. Package Type Check (CRITICAL)
    # Container Images cannot use Layers. They must embed defender in Dockerfile.
    if function_config.get('PackageType') == 'Image':
        return False, "Skipping: Deployed as Container Image (Requires Dockerfile embedding)"

    # 2. Architecture Check (CRITICAL)
    # Prisma Defender currently does not support ARM64 (Graviton).
    architectures = function_config.get('Architectures', ['x86_64'])
    if 'arm64' in architectures:
        return False, "Skipping: ARM64 Architecture not supported by Defender Layer"

    # 3. Runtime Check
    runtime = function_config.get('Runtime', '')
    if runtime not in SUPPORTED_RUNTIMES:
        return False, f"Skipping: Unsupported Runtime ({runtime})"

    # 4. Memory Headroom Check
    # Defender adds ~50-100MB overhead depending on load. 128MB is risky.
    memory = function_config.get('MemorySize', 128)
    if memory < MIN_MEMORY_MB:
        return False, f"Risk: Memory too low ({memory}MB). Minimum safe requires {MIN_MEMORY_MB}MB to avoid OOM."

    # 5. Timeout Buffer Check
    # Defender adds cold-start latency. If function is near 15min limit, we risk timing out.
    timeout = function_config.get('Timeout', 3)
    if timeout > (MAX_TIMEOUT_SEC - TIMEOUT_BUFFER_SEC):
        return False, f"Risk: Timeout configured to {timeout}s. Too close to AWS limit ({MAX_TIMEOUT_SEC}s) to safely add overhead."

    # 6. Layer Limit Check
    current_layers = function_config.get('Layers', [])
    if len(current_layers) >= MAX_LAYERS:
        return False, f"Skipping: Max Layers reached ({len(current_layers)}/{MAX_LAYERS})"

    return True, "Safe"

def deploy_defender(client, function_config, layer_arn):
    func_name = function_config['FunctionName']
    current_layers = [l['Arn'] for l in function_config.get('Layers', [])]
    
    # Append Defender Layer
    new_layers = current_layers + [layer_arn]
    
    # Merge Environment Variables
    current_env = function_config.get('Environment', {}).get('Variables', {})
    new_env = current_env.copy()
    
    # Prisma Specific Vars
    new_env['TW_POLICY'] = func_name
    new_env['AWS_LAMBDA_EXEC_WRAPPER'] = '/opt/twistlock/wrapper.sh'

    if DRY_RUN:
        logger.info(f"[DRY RUN] Would protect {func_name} (Memory: {function_config['MemorySize']}MB, Timeout: {function_config['Timeout']}s)")
        return

    try:
        client.update_function_configuration(
            FunctionName=func_name,
            Layers=new_layers,
            Environment={'Variables': new_env}
        )
        logger.info(f"✅ Protected: {func_name}")
    except ClientError as e:
        logger.error(f"❌ AWS Error on {func_name}: {e}")

def process_region(region):
    if region not in LAYER_ARNS:
        return

    logger.info(f"--- Scanning Region: {region} ---")
    client = get_lambda_client(region)
    layer_arn = LAYER_ARNS[region]
    
    paginator = client.get_paginator('list_functions')
    
    for page in paginator.paginate():
        for func in page['Functions']:
            func_name = func['FunctionName']
            
            # Check if already protected
            if is_protected(func):
                continue
            
            # Deep Risk Assessment
            is_safe, reason = assess_risk(func)
            
            if is_safe:
                deploy_defender(client, func, layer_arn)
            else:
                # Log failures as Warnings so we have an audit trail of UNPROTECTED functions
                logger.warning(f"⚠️  Unprotected {func_name}: {reason}")

def main():
    for region in LAYER_ARNS.keys():
        process_region(region)

def lambda_handler(event, context):
    main()

if __name__ == '__main__':
    main()

Why this V2 Script is Safer
Container Image Bypass (PackageType):

Logic: if PackageType == 'Image': return False

Reason: Container images are immutable. You cannot UpdateFunctionConfiguration to add a layer to them. Trying to do so causes an AWS API error. This script correctly skips them (you must secure these during the Docker build process instead).

ARM64 Protection (Architectures):

Logic: if 'arm64' in Architectures: return False

Reason: Prisma Cloud Defender layers are compiled binaries. The standard layer is x86_64. If you force this onto an ARM64 function, the function will crash immediately upon invocation with an "Exec format error".

Memory Safe-Guards (MemorySize):

Logic: if memory < 256: return False

Reason: The Defender is a lightweight process, but it is not zero-weight. It typically consumes 30-70MB of RAM. If a user deploys a generic "Hello World" function with the default 128MB, adding the Defender will likely trigger an Out of Memory crash, taking down the application.

Timeout Buffer (Timeout):

Logic: if timeout > 870: return False

Reason: AWS Lambda hard kills functions at 15 minutes (900s). If you have a long-running data processing job that takes 14m 55s, adding the Defender (which scans processes on startup) might push the execution time over 15m, causing the function to fail. We leave a 30s buffer.

How to handle the "Exceptions" (What the script skips)
Since the script now skips Risky functions, you need a process to handle them:

For Container Images: You must add the Prisma Defender into the Dockerfile (COPY twistlock-defender-serverless /opt/) during your CI/CD build.

For ARM64: You must either migrate to x86_64 or wait for Prisma to release an ARM64-compatible layer (and update the script to map arm64 -> arm_layer_arn).

For Low Memory/Timeout: You must manually increase the Memory/Timeout settings in AWS before this script allows itself to attach the Defender.


{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "LambdaDiscovery",
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration"
            ],
            "Resource": "*"
        },
        {
            "Sid": "LambdaProtection",
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionConfiguration"
            ],
            "Resource": [
                "arn:aws:lambda:*:123456789012:function:*"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:ResourceTag/SecurityScan": "true"
                }
            }
        },
        {
            "Sid": "LoggingEssentials",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
