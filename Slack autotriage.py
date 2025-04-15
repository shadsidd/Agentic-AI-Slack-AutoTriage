import os
import json
import re
from datetime import datetime
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.reasoning import ReasoningTools
from agno.vectordb.pgvector import PgVector, SearchType
from agno.embedder.openai import OpenAIEmbedder
from agno.document.base import Document
import hashlib
from agno.tools.slack import SlackTools
from agno.knowledge.pdf_url import PDFUrlKnowledgeBase

# Import sample data from the separate file
from sample_data import slack_messages, sample_alerts

# Initialize PGVector with proper configuration
try:
    db_url = "postgresql+psycopg://ai:ai@localhost:5532/ai"
    vector_db = PgVector(
        table_name="security_alerts",
        db_url=db_url,
        search_type=SearchType.hybrid,
        embedder=OpenAIEmbedder(id="text-embedding-3-small"),
        vector_score_weight=0.65,
        prefix_match=True 
    )
    print("Successfully initialized PgVector")
    
    # Drop the existing table if it exists and create a new one with correct dimensions
    vector_db.drop()  # Drop the existing table
    vector_db.create()  # Create a new table with correct dimensions
    print("Created security_alerts table in the database with correct dimensions.")
except Exception as e:
    print(f"Error initializing database: {str(e)}")
    raise

# Create Document objects from sample alerts
documents = []
for i, alert in enumerate(sample_alerts):
    # Create a unique string by combining multiple fields
    unique_str = f"{alert['description']}_{alert['timestamp']}_{i}"
    doc_id = hashlib.md5(unique_str.encode()).hexdigest()
    
    doc = Document(
        id=doc_id,
        name=alert["title"],
        content=alert["description"],
        meta_data={
            "alert_type": alert["alert_type"],
            "account": alert["account"],
            "region": alert["region"],
            "instance": alert["instance"],
            "source_ip": alert["source_ip"],
            "severity": alert["severity"],
            "mfa_used": alert["mfa_used"],
            "timestamp": alert["timestamp"],
            "threat_details": alert["threat_details"]
        }
    )
    documents.append(doc)

# Insert documents into PGVector
vector_db.upsert(documents=documents)

# Create knowledge base using the same vector_db instance
knowledge_base = PDFUrlKnowledgeBase(
    urls=[],  # No URLs to load - we'll use existing data
    vector_db=vector_db  # Reuse the existing vector_db instance
)

# Load the knowledge base
knowledge_base.load(recreate=False)

print(f"Inserted {len(documents)} sample alerts into PGVector")

# Normalize Slack messages
def normalize_slack_message(message):
    """
    Normalize a Slack message into a structured alert format.
    
    Args:
        message (dict): A dictionary containing 'text' and 'timestamp' keys
        
    Returns:
        dict: A normalized alert dictionary with consistent structure
    """
    text = message["text"]
    timestamp = message["timestamp"]
    
    # Initialize with default values
    normalized = {
        "alert_type": "Unknown",
        "title": "Unknown",
        "description": "",
        "account": "Unknown",
        "region": "Unknown",
        "instance": None,
        "source_ip": None,
        "severity": "Unknown",
        "mfa_used": "None",
        "timestamp": timestamp,
        "threat_details": None
    }
    
    # Split message into lines for easier parsing
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    
    # Extract alert type from first line
    if lines:
        first_line = lines[0]
        if "JR-Praetorian" in first_line:
            normalized["alert_type"] = "JR-Praetorian"
        elif "AWS-Moody" in first_line:
            normalized["alert_type"] = "AWS-Moody"
    
    # Extract description (usually the second line)
    if len(lines) > 1:
        normalized["description"] = lines[1]
    elif lines:
        normalized["description"] = lines[0]
    
    # Define patterns for extracting information
    patterns = {
        "account": [r"Account:?\s*([^;]+)", r"Account Name:?\s*([^;]+)"],
        "region": [r"Region:?\s*([^;]+)"],
        "instance": [r"Instance:?\s*([^,]+)"],
        "severity": [r"Severity:?\s*(\d+)"],
        "mfa_used": [r"MFA-USED:?\s*([^\s]+)"],
        "source_ip": [r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"]
    }
    
    # Extract information using patterns
    for line in lines:
        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, line)
                if match:
                    normalized[field] = match.group(1).strip()
                    break
    
    # Determine threat details and title based on description
    description = normalized["description"].lower()
    threat_mapping = {
        "ssh brute force": ("Brute force attack", "SSH Brute Force Attack"),
        "unprotected port": ("Port scanning", "Unprotected Port Probed"),
        "command was executed": ("Potential credential compromise", "Command Execution in Pod"),
        "credentials": ("Unauthorized access", "Credential Misuse") if "remote" in description else (None, None),
        "instance: tm-": ("Port scanning", "Port Scanning Detected")
    }
    
    for key, (threat, title) in threat_mapping.items():
        if key in description:
            if threat:
                normalized["threat_details"] = threat
            if title:
                normalized["title"] = title
            break
    
    return normalized

normalized_alerts = [normalize_slack_message(msg) for msg in slack_messages]
print("Normalized Slack messages:", json.dumps(normalized_alerts, indent=2))

# Helper function to create agents with common configuration
def create_agent(name, role, instructions, tools=None, knowledge=None, search_knowledge=False):
    """Create an agent with common configuration"""
    if tools is None:
        tools = [ReasoningTools(add_instructions=True)]
    
    return Agent(
        name=name,
        role=role,
        model=OpenAIChat(id="gpt-4o"),
        tools=tools,
        knowledge=knowledge,
        search_knowledge=search_knowledge,
        instructions=instructions
    )

# Define Agents
classifier_agent = Agent(
    name="Alert Classifier",
    role="Classify security alerts",
    #model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Analyze the alert description and threat details to classify it into one of these categories:",
        "- Phishing: Attempts to deceive users into revealing sensitive information",
        "- Malware: Software designed to harm systems or steal data",
        "- Unusual Login: Suspicious authentication attempts or access patterns",
        "- Credential Compromise: Stolen or misused credentials",
        "- Network Attack: Port scanning, brute force, or other network-based attacks",
        "- Other: Any other security concern not covered above",
        "Return ONLY the category name as a string."
    ]
)

triage_agent = Agent(
    name="Triage Agent",
    role="Assess risk and suggest actions",
    #model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)],
    knowledge=knowledge_base,
    search_knowledge=True,
    instructions=[
        "Assess the risk level (LOW, MEDIUM, HIGH) based on:",
        "1. Severity score (1-10): 1-3=Low, 4-7=Medium, 8-10=High",
        "2. Threat details: More specific threats indicate higher risk",
        "3. MFA usage: None=Higher risk, Used=Lower risk",
        "4. Similar past alerts: Check if similar alerts were previously marked as false positives or critical",
        
        "Auto-triage rules:",
        "- If similar past alerts were marked as 'false_positive' or 'not_critical', classify as LOW risk with 'Monitor only' action",
        "- If similar past alerts were marked as 'critical', escalate to HIGH risk with proactive actions",
        "- Otherwise, perform standard risk assessment",
        
        "Return a JSON with:",
        "- risk_level: LOW, MEDIUM, or HIGH",
        "- confidence: HIGH, MEDIUM, or LOW",
        "- reasoning: Brief explanation of the assessment",
        "- recommended_actions: List of specific actions to take"
    ]
)

escalation_agent = Agent(
    name="Escalation Agent",
    role="Escalate high-risk alerts",
    #model=OpenAIChat(id="gpt-4o"),
    instructions=[
        "Determine if the alert requires immediate escalation based on:",
        "1. Risk level (HIGH requires escalation)",
        "2. Severity score (8-10 requires escalation)",
        "3. Threat type (credential compromise, malware, or critical system access)",
        
        "If escalation is needed, draft a concise Slack message that:",
        "1. Tags @security-team",
        "2. Includes alert title and risk level in the first line",
        "3. Summarizes the threat in 1-2 sentences",
        "4. Lists 2-3 immediate actions to take",
        "5. Uses appropriate urgency indicators (e.g., 'URGENT', 'CRITICAL')",
        
        "If no escalation is needed, return 'No escalation required'."
    ]
)

remediation_agent = Agent(
    name="Remediation Agent",
    role="Suggest remediation steps",
    instructions=[
        "Based on the alert type and risk level, provide specific remediation steps:",
        
        "For each remediation plan, include:",
        "1. IMMEDIATE actions (within 1 hour)",
        "2. SHORT-TERM actions (within 24 hours)",
        "3. LONG-TERM actions (within 1 week)",
        
        "Format the response in markdown with:",
        "## Immediate Actions",
        "- Action 1: [specific step]",
        "- Action 2: [specific step]",
        
        "## Short-term Actions",
        "- Action 1: [specific step]",
        "- Action 2: [specific step]",
        
        "## Long-term Actions",
        "- Action 1: [specific step]",
        "- Action 2: [specific step]",
        
        "Be specific and actionable. Include commands where appropriate."
    ]
)

response_generator = Agent(
    name="Response Generator",
    role="Format final response",
    #model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Create a well-formatted, concise response that combines all agent outputs:",
        
        "Format the response in markdown with these sections:",
        "## Alert Summary",
        "- Title: [alert title]",
        "- Category: [classification]",
        "- Risk Level: [LOW/MEDIUM/HIGH]",
        "- Severity: [1-10]",
        
        "## Assessment",
        "- Brief 1-2 sentence assessment of the threat",
        "- Key indicators that influenced the risk level",
        
        "## Recommended Actions",
        "- List of 3-5 most important actions to take",
        
        "## Escalation Status",
        "- Whether the alert has been escalated",
        "- If escalated, include the escalation message",
        
        "Keep the entire response under 15 lines. Use bullet points for clarity."
    ]
)

# Coordinator Agent with Team
coordinator_agent = Agent(
    name="Coordinator Agent",
    team=[classifier_agent, triage_agent, escalation_agent, remediation_agent, response_generator],
    model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Coordinate the processing of each alert through the following workflow:",
        
        "1. CLASSIFICATION: Use the Alert Classifier to categorize the alert",
        "2. RISK ASSESSMENT: Use the Triage Agent to determine risk level and initial actions",
        "3. ESCALATION CHECK: If risk is HIGH, use the Escalation Agent to notify security team",
        "4. REMEDIATION PLANNING: Use the Remediation Agent to suggest specific actions",
        "5. RESPONSE FORMATTING: Use the Response Generator to create the final output",
        
        "For each step:",
        "- Pass the complete alert data to each agent",
        "- Capture and validate the output before proceeding to the next step",
        "- If any agent fails, log the error and continue with available information",
        
        "Return the final formatted response from the Response Generator."
    ]
)

# Process each normalized alert
for alert in normalized_alerts:
    response = coordinator_agent.run(json.dumps(alert))
    response_content = response.content if hasattr(response, "content") else response
    print("Processed Alert Response:")
    print(response_content)
    print("-" * 50)