The 4KB Environment Variable Trap:

Fact: AWS Lambda has a hard limit of 4KB (4096 bytes) for all environment variables combined.

Risk: If a function already has 3.8KB of variables, adding TW_POLICY (which can be long) and AWS_LAMBDA_EXEC_WRAPPER will cause the deployment to fail instantly with InvalidParameterValueException.

Fix: We must calculate the size of the existing variables + new variables before applying.

VPC Connectivity (The "Black Hole" Scenario):

Fact: If a Lambda is in a VPC, it loses internet access unless it has a NAT Gateway.

Risk: The Prisma Defender needs to talk to your Console (e.g., twistlock.corp.com:8083) to get its policy. If you add the Defender to a VPC-Lambda with no NAT, the Defender will try to connect, timeout, and crash your function (or cause massive latency).

Fix: Detect if VpcConfig is active and warn the user to verify NAT/Firewall rules.

Ephemeral Storage (/tmp) Collision:

Fact: The Defender agent writes logs and temporary files to /tmp.

Risk: If your function is a data-heavy ETL job that fills up the default 512MB /tmp, adding the Defender (which fights for that same space) can cause No space left on device errors.

Fix: Warn if Ephemeral Storage is set to the default minimum (512MB) and memory is low.

SnapStart Incompatibility:

Fact: AWS SnapStart (currently Java-focused but expanding) freezes the execution environment.

Risk: Modifying layers or variables on a SnapStart-enabled function requires re-publishing versions to take effect, and some extensions don't support the snapshot restoration phase correctly.

Fix: Skip any function where SnapStart is enabled.



import boto3
import logging
import json
import datetime
from botocore.exceptions import ClientError

# ================= CONFIGURATION =================
# Region Map (Update with your specific Layer ARNs)
LAYER_ARNS = {
    'us-east-1': 'arn:aws:lambda:us-east-1:123456789012:layer:twistlock-defender:1',
}

SUPPORTED_RUNTIMES = [
    'python3.8', 'python3.9', 'python3.10', 'python3.11', 'python3.12',
    'nodejs16.x', 'nodejs18.x', 'nodejs20.x'
]

# --- SAFETY THRESHOLDS ---
MIN_MEMORY_MB = 256
MAX_ENV_VAR_SIZE_BYTES = 4096  # AWS Hard Limit
TIMEOUT_BUFFER_SEC = 30
MAX_TIMEOUT_SEC = 900
THROTTLE_LOOKBACK_HRS = 24

# Set True to AUDIT only. Set False to APPLY changes.
DRY_RUN = True 
# ===============================================

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger()

def get_clients(region):
    return {
        'lambda': boto3.client('lambda', region_name=region),
        'cw': boto3.client('cloudwatch', region_name=region)
    }

def calculate_env_size(env_vars):
    """Calculates the total size of environment variables in bytes."""
    size = 0
    for k, v in env_vars.items():
        size += len(str(k)) + len(str(v))
    return size

def is_protected(function_config):
    layers = function_config.get('Layers', [])
    for layer in layers:
        if 'twistlock' in layer['Arn'] or 'prisma' in layer['Arn']:
            return True
    env = function_config.get('Environment', {}).get('Variables', {})
    return 'TW_POLICY' in env

def check_throttling(cw_client, func_name):
    """Checks for ANY throttling in the last 24 hours."""
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(hours=THROTTLE_LOOKBACK_HRS)
    try:
        resp = cw_client.get_metric_statistics(
            Namespace='AWS/Lambda', MetricName='Throttles',
            Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
            StartTime=start_time, EndTime=end_time, Period=86400, Statistics=['Sum']
        )
        if resp['Datapoints'] and resp['Datapoints'][0]['Sum'] > 0:
            return True
    except:
        pass
    return False

def assess_risk_deep_dive(clients, function_config):
    """
    Performs rigorous checks against AWS Limitations.
    """
    func_name = function_config['FunctionName']
    
    # 1. HARDWARE & RUNTIME (Basic Checks)
    if function_config.get('PackageType') == 'Image':
        return False, "Skipping: Container Image (Requires Dockerfile embedding)"
    
    if 'arm64' in function_config.get('Architectures', ['x86_64']):
        return False, "Skipping: ARM64 Architecture not supported"
        
    if function_config.get('Runtime') not in SUPPORTED_RUNTIMES:
        return False, "Skipping: Unsupported Runtime"

    # 2. STABILITY (Memory/Timeout)
    if function_config.get('MemorySize', 128) < MIN_MEMORY_MB:
        return False, f"Risk: Low Memory (<{MIN_MEMORY_MB}MB). Risk of OOM."

    timeout = function_config.get('Timeout', 3)
    if timeout > (MAX_TIMEOUT_SEC - TIMEOUT_BUFFER_SEC):
        return False, "Risk: Timeout too close to 15min limit."

    # 3. ENVIRONMENT VARIABLE QUOTA (The 4KB Trap)
    current_env = function_config.get('Environment', {}).get('Variables', {})
    # Estimate size of NEW variables we will add
    new_vars_size = len("TW_POLICY") + len(func_name) + len("AWS_LAMBDA_EXEC_WRAPPER") + len("/opt/twistlock/wrapper.sh")
    total_size = calculate_env_size(current_env) + new_vars_size
    
    if total_size >= MAX_ENV_VAR_SIZE_BYTES:
        return False, f"CRITICAL: Env Vars too full ({total_size}/{MAX_ENV_VAR_SIZE_BYTES} bytes). Adding Defender will crash deployment."

    # 4. VPC & CONNECTIVITY (The Black Hole)
    vpc_config = function_config.get('VpcConfig', {})
    if vpc_config.get('SubnetIds') and not vpc_config.get('SecurityGroupIds'):
        # This is a loose check. Ideally, we need to check routing tables for NAT, 
        # but that is too complex for this script. We warn instead.
        pass # Just noting existence. Logic below handles warning.
    
    if vpc_config.get('SubnetIds'):
         logger.warning(f"  ⚠️  [VPC CHECK] {func_name} is in a VPC. Ensure it has NAT Gateway access to reach Prisma Console, or Defender will timeout.")

    # 5. SNAPSTART (Java/Future Python)
    if function_config.get('SnapStart', {}).get('ApplyOn') != 'None':
        return False, "Skipping: SnapStart enabled. Modifying layers requires complex version publishing."

    # 6. THROTTLING HISTORY
    if check_throttling(clients['cw'], func_name):
        return False, "Risk: Function was throttled in last 24h. Too unstable to modify."

    return True, "Safe"

def deploy_defender(client, function_config, layer_arn):
    func_name = function_config['FunctionName']
    
    # Logic to merge layers
    current_layers = [l['Arn'] for l in function_config.get('Layers', [])]
    if len(current_layers) >= 5:
        logger.warning(f"🚫 SKIPPED {func_name}: Max Layers (5) reached.")
        return

    new_layers = current_layers + [layer_arn]
    
    # Logic to merge Env Vars
    current_env = function_config.get('Environment', {}).get('Variables', {})
    new_env = current_env.copy()
    new_env['TW_POLICY'] = func_name
    new_env['AWS_LAMBDA_EXEC_WRAPPER'] = '/opt/twistlock/wrapper.sh'

    if DRY_RUN:
        logger.info(f"✅ [DRY RUN] Would PROTECT {func_name}")
        return

    try:
        client.update_function_configuration(
            FunctionName=func_name,
            Layers=new_layers,
            Environment={'Variables': new_env}
        )
        logger.info(f"🚀 PROTECTED: {func_name}")
    except ClientError as e:
        logger.error(f"❌ Failed to update {func_name}: {e}")

def process_region(region):
    if region not in LAYER_ARNS: return

    logger.info(f"--- Scanning Region: {region} ---")
    clients = get_clients(region)
    layer_arn = LAYER_ARNS[region]
    
    paginator = clients['lambda'].get_paginator('list_functions')
    
    for page in paginator.paginate():
        for func in page['Functions']:
            func_name = func['FunctionName']
            
            if is_protected(func):
                continue
            
            is_safe, reason = assess_risk_deep_dive(clients, func)
            
            if is_safe:
                deploy_defender(clients['lambda'], func, layer_arn)
            else:
                logger.warning(f"🚫 SKIPPED {func_name}: {reason}")

def main():
    for region in LAYER_ARNS.keys():
        process_region(region)

def lambda_handler(event, context):
    main()

if __name__ == '__main__':
    main()



use this flow to explain why the script is safe.

Management Summary for this Script
Safety First: It calculates byte-level quotas (4KB Env Var limit) that normally cause "silent failures."

Network Awareness: It flags VPC functions that might black-hole traffic if they lack a NAT Gateway.

Stability: It looks back 24 hours at CloudWatch metrics to ensure we don't touch "stressed" functions.

Compliance: It skips unsupported architectures (ARM64) and deployment types (Containers) to prevent crashing valid workloads.
