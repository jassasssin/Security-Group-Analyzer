from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Optional
import uuid
from datetime import datetime, timezone
import boto3  # Added for AWS integration

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# AWS Connection Setup (New)
aws_region = os.environ.get('AWS_DEFAULT_REGION', 'eu-north-1')
aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
target_sg_id = os.environ.get('TARGET_SECURITY_GROUP_ID')

try:
    if aws_access_key and aws_secret_key:
        ec2_client = boto3.client(
            'ec2',
            region_name=aws_region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
    else:
        ec2_client = None
except Exception as e:
    print(f"AWS Client Initialization Failed: {e}")
    ec2_client = None

# Create the main app without a prefix
app = FastAPI(title="Security Group Misconfiguration Simulator")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# ==================== Models ====================

class SecurityRule(BaseModel):
    """Represents a single security group rule"""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    protocol: str  # TCP, UDP, ICMP, ALL
    port_range: str  # e.g., "22", "80", "0-65535"
    source_ip: str  # e.g., "0.0.0.0/0", "192.168.1.0/24"
    description: str
    direction: str = "inbound"  # inbound or outbound

class SecurityGroup(BaseModel):
    """Represents a security group configuration"""
    group_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    group_name: str
    rules: List[SecurityRule]
    is_vulnerable: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RiskAssessment(BaseModel):
    """Risk assessment for a security rule"""
    rule_id: str
    severity: str  # Critical, High, Medium, Low
    risk_score: int  # 0-100
    vulnerability_type: str
    attack_scenarios: List[str]
    financial_risk: str
    recommendation: str

class SecurityAnalysisResult(BaseModel):
    """Complete analysis result"""
    group_id: str
    total_rules: int
    vulnerable_rules: int
    risk_assessments: List[RiskAssessment]
    overall_security_score: int  # 0-100
    security_posture: str  # Critical, Poor, Fair, Good, Excellent

class SecurityChecklistItem(BaseModel):
    """Security checklist item"""
    item_id: str
    category: str
    check_description: str
    is_compliant: bool
    priority: str  # Critical, High, Medium, Low

class AuditLog(BaseModel):
    """Audit log entry"""
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: str  # analyzed, fixed, viewed_checklist
    user_id: str = "student"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict
    security_score_before: Optional[int] = None
    security_score_after: Optional[int] = None

class AuditLogCreate(BaseModel):
    action: str
    user_id: str = "student"
    details: Dict
    security_score_before: Optional[int] = None
    security_score_after: Optional[int] = None


# ==================== Security Logic ====================

def get_vulnerable_security_group() -> SecurityGroup:
    """Fetch LIVE security group configuration from AWS, with fallback to original data"""
    
    # 1. ATTEMPT LIVE AWS FETCH
    if ec2_client and target_sg_id:
        try:
            response = ec2_client.describe_security_groups(GroupIds=[target_sg_id])
            sg_data = response['SecurityGroups'][0]
            
            live_rules = []
            for ip_perm in sg_data.get('IpPermissions', []):
                protocol = str(ip_perm.get('IpProtocol', 'ALL'))
                if protocol == '-1':
                    protocol = 'ALL'
                    port_range = '0-65535'
                else:
                    protocol = protocol.upper()
                    from_port = ip_perm.get('FromPort', '')
                    to_port = ip_perm.get('ToPort', '')
                    port_range = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"

                for ip_range in ip_perm.get('IpRanges', []):
                    # Only add if it's a valid CIDR representation
                    live_rules.append(SecurityRule(
                        protocol=protocol,
                        port_range=port_range,
                        source_ip=ip_range.get('CidrIp', '0.0.0.0/0'),
                        description=ip_range.get('Description', f"[LIVE AWS] {protocol} Port: {port_range}"),
                        direction="inbound"
                    ))

            # Check if any rule exposes to the entire internet
            is_vulnerable = any(r.source_ip == "0.0.0.0/0" for r in live_rules)
            
            return SecurityGroup(
                group_id=target_sg_id,
                group_name=sg_data.get('GroupName', 'live-aws-production-sg'),
                rules=live_rules,
                is_vulnerable=is_vulnerable
            )
        except Exception as e:
            print(f"Failed to fetch from AWS, falling back to dummy data: {e}")
    
    # 2. FALLBACK TO ORIGINAL HARDCODED DATA (Safety Net)
    vulnerable_rules = [
        SecurityRule(protocol="ALL", port_range="0-65535", source_ip="0.0.0.0/0", description="Allow all traffic from anywhere", direction="inbound"),
        SecurityRule(protocol="TCP", port_range="22", source_ip="0.0.0.0/0", description="SSH access from anywhere", direction="inbound"),
        SecurityRule(protocol="TCP", port_range="3389", source_ip="0.0.0.0/0", description="RDP access from anywhere", direction="inbound"),
        SecurityRule(protocol="TCP", port_range="3306", source_ip="0.0.0.0/0", description="MySQL database exposed", direction="inbound"),
        SecurityRule(protocol="TCP", port_range="5432", source_ip="0.0.0.0/0", description="PostgreSQL database exposed", direction="inbound"),
        SecurityRule(protocol="TCP", port_range="27017", source_ip="0.0.0.0/0", description="MongoDB database exposed", direction="inbound"),
    ]
    return SecurityGroup(
        group_name="prod-web-server-sg",
        rules=vulnerable_rules,
        is_vulnerable=True
    )

def get_secure_security_group() -> SecurityGroup:
    """Generate a secure security group configuration following least privilege"""
    secure_rules = [
        SecurityRule(
            protocol="TCP",
            port_range="80",
            source_ip="0.0.0.0/0",
            description="HTTP access for web traffic",
            direction="inbound"
        ),
        SecurityRule(
            protocol="TCP",
            port_range="443",
            source_ip="0.0.0.0/0",
            description="HTTPS access for secure web traffic",
            direction="inbound"
        ),
        SecurityRule(
            protocol="TCP",
            port_range="22",
            source_ip="203.0.113.0/24",
            description="SSH access from corporate network only",
            direction="inbound"
        ),
    ]
    
    return SecurityGroup(
        group_name="prod-web-server-sg-hardened",
        rules=secure_rules,
        is_vulnerable=False
    )

def analyze_security_rule(rule: SecurityRule) -> Optional[RiskAssessment]:
    """Analyze a single security rule for vulnerabilities"""
    
    # Check if source IP is too permissive
    is_public = rule.source_ip in ["0.0.0.0/0", "::/0"]
    
    if not is_public:
        return None  # Rule is properly restricted
    
    # Critical vulnerabilities
    if rule.protocol == "ALL" or rule.port_range == "0-65535":
        return RiskAssessment(
            rule_id=rule.rule_id,
            severity="Critical",
            risk_score=100,
            vulnerability_type="Complete Network Exposure",
            attack_scenarios=[
                "Unrestricted access to ALL services",
                "DDoS attacks on any port",
                "Exploitation of any vulnerable service",
                "Data exfiltration through any protocol",
                "Lateral movement opportunities"
            ],
            financial_risk="$100,000 - $1,000,000+ (Data breach, ransomware, downtime)",
            recommendation="IMMEDIATE ACTION: Remove this rule and implement specific port-based rules with source IP restrictions"
        )
    
    # SSH exposure (port 22)
    if rule.port_range == "22":
        return RiskAssessment(
            rule_id=rule.rule_id,
            severity="Critical",
            risk_score=95,
            vulnerability_type="SSH Brute Force Exposure",
            attack_scenarios=[
                "SSH brute force attacks from anywhere",
                "Credential stuffing attempts",
                "Unauthorized root access",
                "Server takeover and data theft",
                "Installation of backdoors and malware"
            ],
            financial_risk="$50,000 - $500,000 (System compromise, data breach)",
            recommendation="Restrict SSH access to specific IP addresses (corporate VPN/office network). Use SSH keys instead of passwords."
        )
    
    # RDP exposure (port 3389)
    if rule.port_range == "3389":
        return RiskAssessment(
            rule_id=rule.rule_id,
            severity="Critical",
            risk_score=95,
            vulnerability_type="RDP Brute Force Exposure",
            attack_scenarios=[
                "RDP brute force attacks",
                "Remote desktop takeover",
                "Ransomware deployment",
                "Data exfiltration",
                "Lateral movement in network"
            ],
            financial_risk="$100,000 - $2,000,000 (Ransomware, data breach)",
            recommendation="NEVER expose RDP to the internet. Use VPN or bastion host for RDP access."
        )
    
    # Database ports
    database_ports = {
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "27017": "MongoDB",
        "1433": "SQL Server",
        "5984": "CouchDB",
        "6379": "Redis"
    }
    
    if rule.port_range in database_ports:
        db_type = database_ports[rule.port_range]
        return RiskAssessment(
            rule_id=rule.rule_id,
            severity="Critical",
            risk_score=98,
            vulnerability_type=f"{db_type} Database Exposure",
            attack_scenarios=[
                f"Direct {db_type} authentication attacks",
                "SQL injection exploitation",
                "Complete database dump and theft",
                "Data manipulation and corruption",
                "Compliance violations (GDPR, HIPAA, PCI-DSS)"
            ],
            financial_risk="$200,000 - $5,000,000+ (Data breach, regulatory fines)",
            recommendation=f"NEVER expose {db_type} to the internet. Allow access only from application servers within VPC."
        )
    
    # HTTP/HTTPS are generally acceptable from anywhere for web servers
    if rule.port_range in ["80", "443"]:
        return None
    
    # Other ports open to public
    return RiskAssessment(
        rule_id=rule.rule_id,
        severity="High",
        risk_score=75,
        vulnerability_type="Unnecessary Service Exposure",
        attack_scenarios=[
            "Service-specific exploitation",
            "Port scanning and reconnaissance",
            "DoS/DDoS attacks on specific service",
            "Zero-day vulnerability exploitation"
        ],
        financial_risk="$10,000 - $100,000 (Service disruption, exploitation)",
        recommendation="Review if this port needs public access. Restrict to specific IPs if possible."
    )

def analyze_security_group(security_group: SecurityGroup) -> SecurityAnalysisResult:
    """Analyze entire security group and generate risk assessment"""
    risk_assessments = []
    
    for rule in security_group.rules:
        assessment = analyze_security_rule(rule)
        if assessment:
            risk_assessments.append(assessment)
    
    # Calculate overall security score
    if not risk_assessments:
        overall_score = 100
        posture = "Excellent"
    else:
        # Average risk score (lower is better for security)
        avg_risk = sum(r.risk_score for r in risk_assessments) / len(risk_assessments)
        overall_score = max(0, 100 - int(avg_risk))
        
        if overall_score >= 80:
            posture = "Good"
        elif overall_score >= 60:
            posture = "Fair"
        elif overall_score >= 40:
            posture = "Poor"
        else:
            posture = "Critical"
    
    return SecurityAnalysisResult(
        group_id=security_group.group_id,
        total_rules=len(security_group.rules),
        vulnerable_rules=len(risk_assessments),
        risk_assessments=risk_assessments,
        overall_security_score=overall_score,
        security_posture=posture
    )

def generate_security_checklist(security_group: SecurityGroup) -> List[SecurityChecklistItem]:
    """Generate security checklist based on configuration"""
    checklist = []
    
    # Check 1: No unrestricted access
    has_unrestricted = any(
        rule.source_ip == "0.0.0.0/0" and rule.protocol == "ALL"
        for rule in security_group.rules
    )
    checklist.append(SecurityChecklistItem(
        item_id="check-1",
        category="Access Control",
        check_description="No unrestricted access (0.0.0.0/0 on ALL ports)",
        is_compliant=not has_unrestricted,
        priority="Critical"
    ))
    
    # Check 2: SSH restricted
    ssh_rules = [r for r in security_group.rules if r.port_range == "22"]
    ssh_restricted = all(r.source_ip != "0.0.0.0/0" for r in ssh_rules) if ssh_rules else True
    checklist.append(SecurityChecklistItem(
        item_id="check-2",
        category="Remote Access",
        check_description="SSH (port 22) restricted to specific IPs",
        is_compliant=ssh_restricted,
        priority="Critical"
    ))
    
    # Check 3: RDP not exposed
    rdp_exposed = any(
        rule.port_range == "3389" and rule.source_ip == "0.0.0.0/0"
        for rule in security_group.rules
    )
    checklist.append(SecurityChecklistItem(
        item_id="check-3",
        category="Remote Access",
        check_description="RDP (port 3389) not exposed to internet",
        is_compliant=not rdp_exposed,
        priority="Critical"
    ))
    
    # Check 4: Database ports protected
    db_ports = ["3306", "5432", "27017", "1433", "6379"]
    db_exposed = any(
        rule.port_range in db_ports and rule.source_ip == "0.0.0.0/0"
        for rule in security_group.rules
    )
    checklist.append(SecurityChecklistItem(
        item_id="check-4",
        category="Data Protection",
        check_description="Database ports not exposed to internet",
        is_compliant=not db_exposed,
        priority="Critical"
    ))
    
    # Check 5: Least privilege principle
    necessary_ports = ["80", "443", "22"]
    unnecessary_rules = [
        r for r in security_group.rules
        if r.port_range not in necessary_ports and r.port_range != "0-65535"
    ]
    checklist.append(SecurityChecklistItem(
        item_id="check-5",
        category="Principle of Least Privilege",
        check_description="Only necessary ports are open",
        is_compliant=len(unnecessary_rules) == 0,
        priority="High"
    ))
    
    # Check 6: HTTP/HTTPS available for web server
    has_http = any(r.port_range in ["80", "443"] for r in security_group.rules)
    checklist.append(SecurityChecklistItem(
        item_id="check-6",
        category="Service Availability",
        check_description="HTTP/HTTPS ports available for web traffic",
        is_compliant=has_http,
        priority="High"
    ))
    
    # Check 7: No default/common passwords (simulated)
    checklist.append(SecurityChecklistItem(
        item_id="check-7",
        category="Authentication",
        check_description="Strong authentication mechanisms in place",
        is_compliant=True,  # Assumed for simulation
        priority="High"
    ))
    
    # Check 8: Monitoring and logging enabled (simulated)
    checklist.append(SecurityChecklistItem(
        item_id="check-8",
        category="Monitoring",
        check_description="Security monitoring and logging enabled",
        is_compliant=not security_group.is_vulnerable,
        priority="Medium"
    ))
    
    return checklist


# ==================== API Routes ====================

@api_router.get("/")
async def root():
    return {
        "message": "Security Group Misconfiguration Simulator API",
        "version": "1.0",
        "endpoints": [
            "/api/security-groups/vulnerable",
            "/api/security-groups/secure",
            "/api/security-groups/analyze",
            "/api/security-groups/checklist",
            "/api/audit-logs"
        ]
    }

@api_router.get("/security-groups/vulnerable", response_model=SecurityGroup)
async def get_vulnerable_config():
    """Get a vulnerable security group configuration"""
    return get_vulnerable_security_group()

@api_router.get("/security-groups/secure", response_model=SecurityGroup)
async def get_secure_config():
    """Get a secure security group configuration"""
    return get_secure_security_group()

@api_router.post("/security-groups/analyze", response_model=SecurityAnalysisResult)
async def analyze_configuration(security_group: SecurityGroup):
    """Analyze a security group configuration for vulnerabilities"""
    return analyze_security_group(security_group)

@api_router.post("/security-groups/checklist", response_model=List[SecurityChecklistItem])
async def get_checklist(security_group: SecurityGroup):
    """Get security checklist for a configuration"""
    return generate_security_checklist(security_group)

@api_router.post("/audit-logs", response_model=AuditLog)
async def create_audit_log(log_input: AuditLogCreate):
    """Create an audit log entry"""
    log_dict = log_input.model_dump()
    log_obj = AuditLog(**log_dict)
    
    # Convert to dict and serialize datetime to ISO string for MongoDB
    doc = log_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.audit_logs.insert_one(doc)
    return log_obj

@api_router.get("/audit-logs", response_model=List[AuditLog])
async def get_audit_logs():
    """Get all audit logs"""
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(100)
    
    # Convert ISO string timestamps back to datetime objects
    for log in logs:
        if isinstance(log['timestamp'], str):
            log['timestamp'] = datetime.fromisoformat(log['timestamp'])
    
    return logs

@api_router.get("/stats")
async def get_stats():
    """Get statistics about audit logs"""
    total_audits = await db.audit_logs.count_documents({})
    total_fixes = await db.audit_logs.count_documents({"action": "fixed"})
    
    return {
        "total_audits": total_audits,
        "total_fixes_applied": total_fixes,
        "average_improvement": 95  # Simulated
    }


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()