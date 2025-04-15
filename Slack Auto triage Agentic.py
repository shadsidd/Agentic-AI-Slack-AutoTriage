import os
import json
from datetime import datetime
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.reasoning import ReasoningTools
from agno.vectordb.pgvector import PgVector, SearchType
from agno.embedder.fastembed import FastEmbedEmbedder
from agno.document.base import Document
import hashlib
from agno.tools.slack import SlackTools
from agno.knowledge.pdf_url import PDFUrlKnowledgeBase

# Set environment variable to prevent tokenizer parallelism warnings
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Import sample data from the separate file
from sample_data import slack_messages, sample_alerts

# Initialize PGVector with proper configuration
try:
    db_url = "postgresql+psycopg://ai:ai@localhost:5532/ai"
    table_name = "security_alerts"  # Define table name in one place
    
    # Create embedder instance
    embedder = FastEmbedEmbedder()
    
    # Print embedder dimensions for debugging
    test_embedding = embedder.get_embedding("Test sentence")
    print(f"FastEmbed Embedder dimensions: {len(test_embedding)}")
    
    # Drop the existing table if it exists
    temp_vector_db = PgVector(
        table_name=table_name,  # Use the same table name
        db_url=db_url,
        embedder=embedder
    )
    
    # Drop the table if it exists
    try:
        temp_vector_db.drop()
        print(f"Dropped existing {table_name} table")
    except Exception as e:
        print(f"Note: Could not drop table (might not exist): {str(e)}")
    
    # Initialize vector database with the correct embedder
    vector_db = PgVector(
        table_name=table_name,
        db_url=db_url,
        search_type=SearchType.hybrid,
        embedder=embedder,
        vector_score_weight=0.65,
        prefix_match=True 
    )
    print("Successfully initialized PgVector")
    
    # Create the table with the correct dimensions
    vector_db.create()
    print(f"Created {table_name} table in the database with correct dimensions.")
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
try:
    vector_db.upsert(documents=documents)
    print(f"Successfully inserted {len(documents)} documents into {table_name}")
except Exception as e:
    print(f"Error inserting documents: {str(e)}")
    raise

# Create knowledge base with the same table and embedder
knowledge_base = PDFUrlKnowledgeBase(
    urls=[],  # No URLs to load - we'll use existing data
    vector_db=PgVector(
        table_name=table_name,  # Use the same table name
        db_url=db_url,
        search_type=SearchType.hybrid,  # Can be SearchType.vector or SearchType.hybrid
        vector_score_weight=0.5,
        prefix_match=True,  # Enable prefix matching for better keyword search
        embedder=embedder  # Use the same embedder instance
    )
)

# Load the knowledge base (this is important!)
try:
    knowledge_base.load(recreate=False)
    print(f"Successfully loaded knowledge base from {table_name}")
except Exception as e:
    print(f"Error loading knowledge base: {str(e)}")
    raise

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
        "account": [
            (r"Account:?\s*([^;]+)", 1),
            (r"Account Name:?\s*([^;]+)", 1)
        ],
        "region": [
            (r"Region:?\s*([^;]+)", 1)
        ],
        "instance": [
            (r"Instance:?\s*([^,]+)", 1)
        ],
        "severity": [
            (r"Severity:?\s*(\d+)", 1)
        ],
        "mfa_used": [
            (r"MFA-USED:?\s*([^\s]+)", 1)
        ],
        "source_ip": [
            (r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1)
        ]
    }
    
    # Extract information using patterns
    import re
    for line in lines:
        for field, field_patterns in patterns.items():
            for pattern, group_index in field_patterns:
                match = re.search(pattern, line)
                if match:
                    normalized[field] = match.group(group_index).strip()
                    break
    
    # Determine threat details based on description
    description = normalized["description"].lower()
    if "ssh brute force" in description:
        normalized["threat_details"] = "Brute force attack"
    elif "unprotected port" in description:
        normalized["threat_details"] = "Port scanning"
    elif "command was executed" in description:
        normalized["threat_details"] = "Potential credential compromise"
    elif "credentials" in description and "remote" in description:
        normalized["threat_details"] = "Unauthorized access"
    
    # Determine title based on description
    if "ssh brute force" in description:
        normalized["title"] = "SSH Brute Force Attack"
    elif "unprotected port" in description:
        normalized["title"] = "Unprotected Port Probed"
    elif "command was executed" in description:
        normalized["title"] = "Command Execution in Pod"
    elif "credentials" in description and "remote" in description:
        normalized["title"] = "Credential Misuse"
    elif "instance: tm-" in description.lower():
        normalized["title"] = "Port Scanning Detected"
    
    return normalized

normalized_alerts = [normalize_slack_message(msg) for msg in slack_messages]
print("Normalized Slack messages:", json.dumps(normalized_alerts, indent=2))

# Define Agents
classifier_agent = Agent(
    name="Alert Classifier",
    role="Classify security alerts",
    model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Analyze the alert description and threat details to classify it into one of these categories:",
        "- Phishing: Attempts to deceive users into revealing sensitive information",
        "- Malware: Software designed to harm systems or steal data",
        "- Unusual Login: Suspicious authentication attempts or access patterns",
        "- Credential Compromise: Stolen or misused credentials",
        "- Network Attack: Port scanning, brute force, or other network-based attacks",
        "- Other: Any other security concern not covered above",
        "Return ONLY the category name as a string.",
        "If you receive feedback from other agents, incorporate it into your analysis."
    ]
)

triage_agent = Agent(
    name="Triage Agent",
    role="Assess risk and suggest actions",
    model=OpenAIChat(id="gpt-4o"),
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
        "- recommended_actions: List of specific actions to take",
        
        "If you receive feedback from other agents, adjust your assessment accordingly."
    ]
)

escalation_agent = Agent(
    name="Escalation Agent",
    role="Escalate high-risk alerts",
    model=OpenAIChat(id="gpt-4o"),
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
        
        "If no escalation is needed, return 'No escalation required'.",
        
        "If you receive feedback from other agents, adjust your escalation decision accordingly."
    ]
)

remediation_agent = Agent(
    name="Remediation Agent",
    role="Suggest remediation steps",
    model=OpenAIChat(id="gpt-4o"),
    tools=[ReasoningTools(add_instructions=True)], #, SlackTools()],
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
        
        "Be specific and actionable. Include commands where appropriate.",
        
        "If you receive feedback from other agents, adjust your remediation plan accordingly."
    ]
)

response_generator = Agent(
    name="Response Generator",
    role="Format final response",
    model=OpenAIChat(id="gpt-4o"),
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
        
        "Keep the entire response under 15 lines. Use bullet points for clarity.",
        
        "If you receive feedback from other agents, incorporate it into your response."
    ]
)

# Feedback mechanism for agent-to-agent communication
def create_feedback_loop(agents):
    """
    Creates a feedback loop between agents where each agent can provide feedback to others.
    
    Args:
        agents: List of agent objects
        
    Returns:
        dict: A dictionary mapping agent names to their feedback functions
    """
    feedback_functions = {}
    
    for agent in agents:
        agent_name = agent.name
        
        def create_feedback_function(target_agent):
            def provide_feedback(feedback_text):
                # Add feedback to the target agent's context
                target_agent.instructions.append(f"Feedback from {agent_name}: {feedback_text}")
                return f"Feedback provided to {target_agent.name}"
            return provide_feedback
        
        # Create feedback functions for each other agent
        for other_agent in agents:
            if other_agent != agent:
                feedback_functions[f"{agent_name}_to_{other_agent.name}"] = create_feedback_function(other_agent)
    
    return feedback_functions

# Coordinator Agent with Team and Feedback Loop
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
        
        "Enable agent feedback:",
        "- After each agent completes its task, allow other agents to provide feedback",
        "- Incorporate feedback into the next iteration of processing",
        "- If significant feedback is provided, consider re-running an agent with updated context",
        
        "Return the final formatted response from the Response Generator."
    ]
)

# Create feedback functions for agent-to-agent communication
feedback_functions = create_feedback_loop([classifier_agent, triage_agent, escalation_agent, remediation_agent, response_generator])

# Add feedback functions to the coordinator agent's tools
for feedback_name, feedback_func in feedback_functions.items():
    coordinator_agent.tools.append(feedback_func)

# Process each normalized alert with feedback loop
for alert in normalized_alerts:
    # Initial processing
    classification = classifier_agent.run(json.dumps(alert))
    
    # Allow other agents to provide feedback on classification
    triage_feedback = triage_agent.run(f"Review this classification: {classification.content if hasattr(classification, 'content') else classification}")
    feedback_functions["Triage Agent_to_Alert Classifier"]("Consider this feedback: " + triage_feedback.content if hasattr(triage_feedback, 'content') else triage_feedback)
    
    # Process with updated classification
    updated_classification = classifier_agent.run(json.dumps(alert))
    
    # Continue with triage using updated classification
    triage_result = triage_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification))
    
    # Allow other agents to provide feedback on triage
    escalation_feedback = escalation_agent.run(f"Review this triage: {triage_result.content if hasattr(triage_result, 'content') else triage_result}")
    feedback_functions["Escalation Agent_to_Triage Agent"]("Consider this feedback: " + escalation_feedback.content if hasattr(escalation_feedback, 'content') else escalation_feedback)
    
    # Process with updated triage
    updated_triage = triage_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification))
    
    # Continue with escalation using updated triage
    escalation_result = escalation_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification) + "\nTriage: " + (updated_triage.content if hasattr(updated_triage, 'content') else updated_triage))
    
    # Allow other agents to provide feedback on escalation
    remediation_feedback = remediation_agent.run(f"Review this escalation decision: {escalation_result.content if hasattr(escalation_result, 'content') else escalation_result}")
    feedback_functions["Remediation Agent_to_Escalation Agent"]("Consider this feedback: " + remediation_feedback.content if hasattr(remediation_feedback, 'content') else remediation_feedback)
    
    # Process with updated escalation
    updated_escalation = escalation_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification) + "\nTriage: " + (updated_triage.content if hasattr(updated_triage, 'content') else updated_triage))
    
    # Continue with remediation using all updated information
    remediation_result = remediation_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification) + "\nTriage: " + (updated_triage.content if hasattr(updated_triage, 'content') else updated_triage) + "\nEscalation: " + (updated_escalation.content if hasattr(updated_escalation, 'content') else updated_escalation))
    
    # Allow other agents to provide feedback on remediation
    response_feedback = response_generator.run(f"Review this remediation plan: {remediation_result.content if hasattr(remediation_result, 'content') else remediation_result}")
    feedback_functions["Response Generator_to_Remediation Agent"]("Consider this feedback: " + response_feedback.content if hasattr(response_feedback, 'content') else response_feedback)
    
    # Process with updated remediation
    updated_remediation = remediation_agent.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification) + "\nTriage: " + (updated_triage.content if hasattr(updated_triage, 'content') else updated_triage) + "\nEscalation: " + (updated_escalation.content if hasattr(updated_escalation, 'content') else updated_escalation))
    
    # Generate final response with all updated information
    final_response = response_generator.run(json.dumps(alert) + "\nClassification: " + (updated_classification.content if hasattr(updated_classification, 'content') else updated_classification) + "\nTriage: " + (updated_triage.content if hasattr(updated_triage, 'content') else updated_triage) + "\nEscalation: " + (updated_escalation.content if hasattr(updated_escalation, 'content') else updated_escalation) + "\nRemediation: " + (updated_remediation.content if hasattr(updated_remediation, 'content') else updated_remediation))
    
    response_content = final_response.content if hasattr(final_response, 'content') else final_response
    print("Processed Alert Response with Agent Feedback:")
    print(response_content)
    print("-" * 50)