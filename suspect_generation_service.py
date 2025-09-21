"""
Suspect Generation FastAPI Service with LangGraph Integration

This service:
1. Receives anomalies from the Anomaly Detection API
2. Generates root cause suspects using AI and rule-based methods
3. Sends suspects to SQS for further processing
4. Uses LangGraph for workflow orchestration
"""

import json
import logging
import asyncio
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from contextlib import asynccontextmanager
from enum import Enum
from dataclasses import dataclass, asdict

import boto3
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import AnyMessage, add_messages
from typing_extensions import Annotated, TypedDict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL", "https://sqs.ap-southeast-1.amazonaws.com/123456789012/suspects-queue")

class SuspectType(Enum):
    """Types of root cause suspects"""
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    EXTERNAL = "external"
    NETWORK = "network"
    DATABASE = "database"

class SeverityLevel(Enum):
    """Severity levels for suspects"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Suspect:
    """Root cause suspect data structure"""
    id: str
    incident_id: str
    type: SuspectType
    title: str
    description: str
    confidence: float
    severity: SeverityLevel
    evidence: List[str]
    suggested_actions: List[str]
    created_at: str
    metadata: Dict[str, Any]

class SuspectGenerationRequest(BaseModel):
    incident_id: str = Field(..., description="Incident ID")
    anomalies: List[Dict[str, Any]] = Field(..., description="List of detected anomalies")
    context: Optional[Dict[str, Any]] = Field(default={}, description="Additional context")

class SuspectGenerationResponse(BaseModel):
    incident_id: str
    suspects_generated: int
    suspects: List[Dict[str, Any]]
    processing_time_ms: int
    timestamp: str

class WorkflowState(TypedDict):
    """State for the suspect generation workflow"""
    incident_id: str
    anomalies: List[Dict[str, Any]]
    context: Dict[str, Any]
    suspects: List[Suspect]
    messages: Annotated[List[AnyMessage], add_messages]

class SuspectGenerationService:
    def __init__(self):
        self.sqs_client = None
        
        # Initialize AWS SQS client
        try:
            self.sqs_client = boto3.client('sqs', region_name=AWS_REGION)
            logger.info(f"Initialized SQS client for region {AWS_REGION}")
        except Exception as e:
            logger.error(f"Failed to initialize SQS client: {e}")
        
        # Initialize LangGraph workflow
        self.workflow = self._create_workflow()
        
        # Rule-based suspect generation patterns
        self.suspect_patterns = self._initialize_suspect_patterns()
    
    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow for suspect generation"""
        workflow = StateGraph(WorkflowState)
        
        # Add nodes
        workflow.add_node("analyze_anomalies", self.analyze_anomalies_node)
        workflow.add_node("generate_suspects", self.generate_suspects_node)
        workflow.add_node("rank_suspects", self.rank_suspects_node)
        workflow.add_node("send_to_sqs", self.send_to_sqs_node)
        
        # Add edges
        workflow.add_edge(START, "analyze_anomalies")
        workflow.add_edge("analyze_anomalies", "generate_suspects")
        workflow.add_edge("generate_suspects", "rank_suspects")
        workflow.add_edge("rank_suspects", "send_to_sqs")
        workflow.add_edge("send_to_sqs", END)
        
        return workflow.compile()
    
    def _initialize_suspect_patterns(self) -> Dict[str, Dict]:
        """Initialize rule-based patterns for suspect generation"""
        return {
            "performance": {
                "patterns": [
                    {"keywords": ["timeout", "slow", "latency"], "type": SuspectType.INFRASTRUCTURE, "confidence": 0.8},
                    {"keywords": ["memory", "cpu", "resource"], "type": SuspectType.INFRASTRUCTURE, "confidence": 0.9},
                    {"keywords": ["database", "query", "connection"], "type": SuspectType.DATABASE, "confidence": 0.85}
                ]
            },
            "error": {
                "patterns": [
                    {"keywords": ["exception", "error", "failed"], "type": SuspectType.APPLICATION, "confidence": 0.7},
                    {"keywords": ["network", "connection", "unreachable"], "type": SuspectType.NETWORK, "confidence": 0.8},
                    {"keywords": ["config", "configuration", "setting"], "type": SuspectType.CONFIGURATION, "confidence": 0.75}
                ]
            },
            "memory": {
                "patterns": [
                    {"keywords": ["memory", "heap", "oom"], "type": SuspectType.INFRASTRUCTURE, "confidence": 0.9},
                    {"keywords": ["leak", "garbage", "allocation"], "type": SuspectType.APPLICATION, "confidence": 0.85}
                ]
            }
        }
    
    async def analyze_anomalies_node(self, state: WorkflowState) -> WorkflowState:
        """Analyze anomalies to understand patterns"""
        logger.info(f"Analyzing {len(state['anomalies'])} anomalies for incident {state['incident_id']}")
        
        # Group anomalies by type
        anomaly_groups = {}
        for anomaly in state["anomalies"]:
            anomaly_type = anomaly.get("anomaly_type", "unknown")
            if anomaly_type not in anomaly_groups:
                anomaly_groups[anomaly_type] = []
            anomaly_groups[anomaly_type].append(anomaly)
        
        # Add analysis to context
        state["context"]["anomaly_groups"] = anomaly_groups
        state["context"]["total_anomalies"] = len(state["anomalies"])
        
        logger.info(f"Grouped anomalies: {dict((k, len(v)) for k, v in anomaly_groups.items())}")
        
        return state
    
    async def generate_suspects_node(self, state: WorkflowState) -> WorkflowState:
        """Generate suspects based on anomalies"""
        logger.info(f"Generating suspects for incident {state['incident_id']}")
        
        suspects = []
        
        for anomaly in state["anomalies"]:
            # Generate suspects for each anomaly
            anomaly_suspects = self._generate_suspects_for_anomaly(anomaly, state["incident_id"])
            suspects.extend(anomaly_suspects)
        
        # Remove duplicates based on suspect content
        unique_suspects = self._deduplicate_suspects(suspects)
        
        state["suspects"] = unique_suspects
        logger.info(f"Generated {len(unique_suspects)} unique suspects")
        
        return state
    
    def _generate_suspects_for_anomaly(self, anomaly: Dict[str, Any], incident_id: str) -> List[Suspect]:
        """Generate suspects for a single anomaly"""
        suspects = []
        anomaly_type = anomaly.get("anomaly_type", "unknown")
        message = anomaly.get("message", "").lower()
        
        # Get patterns for this anomaly type
        patterns = self.suspect_patterns.get(anomaly_type, {}).get("patterns", [])
        
        for pattern in patterns:
            # Check if any keywords match
            if any(keyword in message for keyword in pattern["keywords"]):
                suspect = Suspect(
                    id=f"suspect_{incident_id}_{len(suspects)}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    incident_id=incident_id,
                    type=pattern["type"],
                    title=self._generate_suspect_title(pattern["type"], anomaly),
                    description=self._generate_suspect_description(pattern["type"], anomaly),
                    confidence=pattern["confidence"] * anomaly.get("confidence", 1.0),
                    severity=self._determine_severity(anomaly),
                    evidence=[anomaly.get("message", ""), f"Anomaly type: {anomaly_type}"],
                    suggested_actions=self._generate_suggested_actions(pattern["type"]),
                    created_at=datetime.utcnow().isoformat() + 'Z',
                    metadata={
                        "anomaly_index": anomaly.get("log_index", -1),
                        "anomaly_timestamp": anomaly.get("timestamp", ""),
                        "service": anomaly.get("service", ""),
                        "features": anomaly.get("features", {})
                    }
                )
                suspects.append(suspect)
        
        # If no patterns matched, generate a generic suspect
        if not suspects:
            generic_suspect = Suspect(
                id=f"suspect_{incident_id}_generic_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                incident_id=incident_id,
                type=SuspectType.APPLICATION,
                title=f"Generic {anomaly_type} anomaly",
                description=f"Detected {anomaly_type} anomaly that requires investigation",
                confidence=0.5,
                severity=self._determine_severity(anomaly),
                evidence=[anomaly.get("message", "")],
                suggested_actions=["Investigate logs", "Check system metrics"],
                created_at=datetime.utcnow().isoformat() + 'Z',
                metadata={
                    "anomaly_index": anomaly.get("log_index", -1),
                    "anomaly_timestamp": anomaly.get("timestamp", ""),
                    "service": anomaly.get("service", "")
                }
            )
            suspects.append(generic_suspect)
        
        return suspects
    
    def _generate_suspect_title(self, suspect_type: SuspectType, anomaly: Dict[str, Any]) -> str:
        """Generate a title for the suspect"""
        service = anomaly.get("service", "Unknown Service")
        anomaly_type = anomaly.get("anomaly_type", "unknown")
        
        titles = {
            SuspectType.INFRASTRUCTURE: f"Infrastructure issue in {service}",
            SuspectType.APPLICATION: f"Application error in {service}",
            SuspectType.DATABASE: f"Database performance issue affecting {service}",
            SuspectType.NETWORK: f"Network connectivity issue for {service}",
            SuspectType.CONFIGURATION: f"Configuration problem in {service}",
            SuspectType.DEPLOYMENT: f"Deployment issue affecting {service}",
            SuspectType.DEPENDENCY: f"Dependency failure impacting {service}",
            SuspectType.EXTERNAL: f"External service issue affecting {service}"
        }
        
        return titles.get(suspect_type, f"{anomaly_type.title()} anomaly in {service}")
    
    def _generate_suspect_description(self, suspect_type: SuspectType, anomaly: Dict[str, Any]) -> str:
        """Generate a description for the suspect"""
        message = anomaly.get("message", "")[:200]  # Truncate long messages
        confidence = anomaly.get("confidence", 0)
        
        return f"Detected {suspect_type.value} issue with confidence {confidence:.2f}. Evidence: {message}"
    
    def _determine_severity(self, anomaly: Dict[str, Any]) -> SeverityLevel:
        """Determine severity based on anomaly characteristics"""
        confidence = anomaly.get("confidence", 0)
        level = anomaly.get("level", "INFO")
        
        if level in ["CRITICAL", "ERROR"] or confidence > 0.9:
            return SeverityLevel.CRITICAL
        elif level == "WARNING" or confidence > 0.7:
            return SeverityLevel.HIGH
        elif confidence > 0.5:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _generate_suggested_actions(self, suspect_type: SuspectType) -> List[str]:
        """Generate suggested actions based on suspect type"""
        actions = {
            SuspectType.INFRASTRUCTURE: [
                "Check system resource utilization",
                "Review infrastructure monitoring dashboards",
                "Verify auto-scaling configurations"
            ],
            SuspectType.APPLICATION: [
                "Review application logs for errors",
                "Check application performance metrics",
                "Verify recent code deployments"
            ],
            SuspectType.DATABASE: [
                "Check database performance metrics",
                "Review slow query logs",
                "Verify database connection pools"
            ],
            SuspectType.NETWORK: [
                "Check network connectivity",
                "Review firewall and security group rules",
                "Verify DNS resolution"
            ],
            SuspectType.CONFIGURATION: [
                "Review recent configuration changes",
                "Verify environment variables",
                "Check configuration file syntax"
            ]
        }
        
        return actions.get(suspect_type, ["Investigate further", "Check system logs"])
    
    def _deduplicate_suspects(self, suspects: List[Suspect]) -> List[Suspect]:
        """Remove duplicate suspects based on content similarity"""
        unique_suspects = []
        seen_signatures = set()
        
        for suspect in suspects:
            # Create a signature based on type, title, and key evidence
            signature = f"{suspect.type.value}:{suspect.title}:{suspect.evidence[0] if suspect.evidence else ''}"
            signature_hash = hash(signature)
            
            if signature_hash not in seen_signatures:
                seen_signatures.add(signature_hash)
                unique_suspects.append(suspect)
        
        return unique_suspects
    
    async def rank_suspects_node(self, state: WorkflowState) -> WorkflowState:
        """Rank suspects by confidence and severity"""
        logger.info(f"Ranking {len(state['suspects'])} suspects")
        
        # Sort by confidence (descending) and then by severity
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1
        }
        
        state["suspects"].sort(
            key=lambda s: (s.confidence, severity_order.get(s.severity, 0)),
            reverse=True
        )
        
        logger.info(f"Ranked suspects by confidence and severity")
        
        return state
    
    async def send_to_sqs_node(self, state: WorkflowState) -> WorkflowState:
        """Send suspects to SQS queue"""
        logger.info(f"Sending {len(state['suspects'])} suspects to SQS")
        
        if not self.sqs_client or not SQS_QUEUE_URL:
            logger.warning("SQS client or queue URL not configured, skipping SQS send")
            return state
        
        try:
            for suspect in state["suspects"]:
                message_body = json.dumps(asdict(suspect), default=str)
                
                response = self.sqs_client.send_message(
                    QueueUrl=SQS_QUEUE_URL,
                    MessageBody=message_body,
                    MessageAttributes={
                        'incident_id': {
                            'StringValue': suspect.incident_id,
                            'DataType': 'String'
                        },
                        'suspect_type': {
                            'StringValue': suspect.type.value,
                            'DataType': 'String'
                        },
                        'severity': {
                            'StringValue': suspect.severity.value,
                            'DataType': 'String'
                        }
                    }
                )
                
                logger.debug(f"Sent suspect {suspect.id} to SQS: {response['MessageId']}")
            
            logger.info(f"Successfully sent {len(state['suspects'])} suspects to SQS")
            
        except Exception as e:
            logger.error(f"Error sending suspects to SQS: {e}")
        
        return state
    
    async def generate_suspects(self, request: SuspectGenerationRequest) -> SuspectGenerationResponse:
        """Main method to generate suspects"""
        start_time = datetime.utcnow()
        logger.info(f"Starting suspect generation for incident {request.incident_id}")
        
        # Initialize workflow state
        initial_state = WorkflowState(
            incident_id=request.incident_id,
            anomalies=request.anomalies,
            context=request.context,
            suspects=[],
            messages=[]
        )
        
        # Run the workflow
        final_state = await self.workflow.ainvoke(initial_state)
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Convert suspects to dict format
        suspects_dict = [asdict(suspect) for suspect in final_state["suspects"]]
        
        # Create response
        response = SuspectGenerationResponse(
            incident_id=request.incident_id,
            suspects_generated=len(suspects_dict),
            suspects=suspects_dict,
            processing_time_ms=int(processing_time),
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )
        
        logger.info(f"Suspect generation completed for incident {request.incident_id}: {response.suspects_generated} suspects generated in {processing_time:.2f}ms")
        return response

# Global service instance
suspect_service = SuspectGenerationService()

# FastAPI app
app = FastAPI(
    title="Suspect Generation Service",
    description="AI-powered root cause suspect generation for incidents",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "suspect-generation", "timestamp": datetime.utcnow().isoformat()}

@app.post("/generate-suspects", response_model=SuspectGenerationResponse)
async def generate_suspects_endpoint(request: SuspectGenerationRequest):
    """Generate root cause suspects from anomalies"""
    try:
        return await suspect_service.generate_suspects(request)
    except Exception as e:
        logger.error(f"Error in suspect generation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
