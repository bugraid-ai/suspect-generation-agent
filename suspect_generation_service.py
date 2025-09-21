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
import httpx
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

# Hybrid Search configuration
HYBRID_SEARCH_URL = os.getenv("HYBRID_SEARCH_API_URL", "http://localhost:8010")
HYBRID_SEARCH_PATH = os.getenv("HYBRID_SEARCH_API_PATH", "/hybrid/test")

# RCA Agent configuration
RCA_AGENT_URL = os.getenv("RCA_AGENT_API_URL", "http://localhost:8001")

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
    historical_context: List[Dict[str, Any]]
    rca_result: Optional[Dict[str, Any]]
    alert_data: Dict[str, Any]
    telemetry: Dict[str, Any]
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
        workflow.add_node("fetch_historical_context", self.fetch_historical_context_node)
        workflow.add_node("trigger_rca_analysis", self.trigger_rca_analysis_node)
        workflow.add_node("send_to_sqs", self.send_to_sqs_node)
        
        # Add edges
        workflow.add_edge(START, "analyze_anomalies")
        workflow.add_edge("analyze_anomalies", "generate_suspects")
        workflow.add_edge("generate_suspects", "rank_suspects")
        workflow.add_edge("rank_suspects", "fetch_historical_context")
        workflow.add_edge("fetch_historical_context", "trigger_rca_analysis")
        workflow.add_edge("trigger_rca_analysis", "send_to_sqs")
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
    
    async def fetch_historical_context_node(self, state: WorkflowState) -> WorkflowState:
        """Fetch historical context using hybrid search"""
        logger.info(f"Fetching historical context for incident {state['incident_id']}")
        
        try:
            # Prepare alerts for hybrid search
            alerts_for_search = []
            
            # Add current incident alert data
            if state.get("alert_data"):
                alerts_for_search.append(state["alert_data"])
            
            # Add suspect information as search context
            for suspect in state["suspects"]:
                suspect_alert = {
                    "title": suspect.title,
                    "description": suspect.description,
                    "service": {"name": state.get("context", {}).get("service", "")},
                    "company_id": state.get("alert_data", {}).get("company_id", ""),
                    "incident_id": state["incident_id"],
                    "environment": os.getenv("ENVIRONMENT", "development"),
                    "tags": [suspect.type.value]
                }
                alerts_for_search.append(suspect_alert)
            
            # Call hybrid search
            historical_context = await self._call_hybrid_search(alerts_for_search)
            state["historical_context"] = historical_context
            
            logger.info(f"Fetched {len(historical_context)} historical incidents for context")
            
        except Exception as e:
            logger.error(f"Failed to fetch historical context: {e}")
            state["historical_context"] = []
        
        return state
    
    async def _call_hybrid_search(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Call the hybrid search service to get historical context"""
        if not HYBRID_SEARCH_URL:
            logger.warning("Hybrid search URL not configured")
            return []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Build query from alerts
                query_parts = []
                for alert in alerts:
                    title = alert.get("title", "")
                    description = alert.get("description", "")
                    service = alert.get("service", {})
                    service_name = service.get("name", "") if isinstance(service, dict) else str(service)
                    
                    parts = [p for p in [title, service_name, description] if p]
                    if parts:
                        query_parts.append(" — ".join(parts))
                
                query_text = " | ".join(query_parts[:3])  # Limit to top 3 for performance
                
                # Prepare hybrid search request
                search_request = {
                    "alerts": alerts,
                    "environment": os.getenv("ENVIRONMENT", "development")
                }
                
                url = f"{HYBRID_SEARCH_URL.rstrip('/')}{HYBRID_SEARCH_PATH}"
                response = await client.post(url, json=search_request)
                
                if response.status_code == 200:
                    result = response.json()
                    hits = result.get("hits", [])
                    
                    # Extract relevant information from search results
                    historical_incidents = []
                    for hit in hits:
                        historical_incidents.append({
                            "incident_id": hit.get("incident_id", ""),
                            "title": hit.get("title", ""),
                            "resolution": hit.get("resolution", ""),
                            "root_cause": hit.get("root_cause", ""),
                            "similarity_score": hit.get("similarity_score", 0),
                            "service": hit.get("service", ""),
                            "timestamp": hit.get("timestamp", "")
                        })
                    
                    return historical_incidents
                else:
                    logger.warning(f"Hybrid search returned {response.status_code}: {response.text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error calling hybrid search: {e}")
            return []
    
    async def trigger_rca_analysis_node(self, state: WorkflowState) -> WorkflowState:
        """Trigger RCA analysis with suspects and historical context"""
        logger.info(f"Triggering RCA analysis for incident {state['incident_id']}")
        
        try:
            # Prepare RCA request
            rca_request = {
                "incident_id": state["incident_id"],
                "suspects": [
                    {
                        "id": suspect.id,
                        "type": suspect.type.value,
                        "title": suspect.title,
                        "description": suspect.description,
                        "confidence": suspect.confidence,
                        "severity": suspect.severity.value,
                        "evidence": suspect.evidence,
                        "suggested_actions": suspect.suggested_actions,
                        "metadata": suspect.metadata
                    }
                    for suspect in state["suspects"]
                ],
                "alert_data": state.get("alert_data", {}),
                "telemetry": state.get("telemetry", {}),
                "context": state.get("context", {}),
                "session_id": state.get("context", {}).get("session_id"),
                "causal_graph": {}
            }
            
            # Call RCA agent
            rca_result = await self._call_rca_agent(rca_request)
            state["rca_result"] = rca_result
            
            logger.info(f"RCA analysis completed for incident {state['incident_id']}")
            
        except Exception as e:
            logger.error(f"Failed to trigger RCA analysis: {e}")
            state["rca_result"] = None
        
        return state
    
    async def _call_rca_agent(self, rca_request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call the RCA agent service"""
        if not RCA_AGENT_URL:
            logger.warning("RCA agent URL not configured")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:  # Longer timeout for RCA
                url = f"{RCA_AGENT_URL.rstrip('/')}/analyze-incident"
                response = await client.post(url, json=rca_request)
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"RCA analysis successful: {result.get('rca_id', 'unknown')}")
                    return result
                else:
                    logger.warning(f"RCA agent returned {response.status_code}: {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error calling RCA agent: {e}")
            return None
    
    async def send_to_sqs_node(self, state: WorkflowState) -> WorkflowState:
        """Send comprehensive analysis results to SQS queue"""
        logger.info(f"Sending analysis results for incident {state['incident_id']} to SQS")
        
        if not self.sqs_client or not SQS_QUEUE_URL:
            logger.warning("SQS client or queue URL not configured, skipping SQS send")
            return state
        
        try:
            # Prepare comprehensive message with suspects, historical context, and RCA results
            comprehensive_message = {
                "message_type": "SUSPECT_GENERATION_COMPLETE",
                "incident_id": state["incident_id"],
                "suspects_count": len(state["suspects"]),
                "suspects": [
                    {
                        "id": suspect.id,
                        "type": suspect.type.value,
                        "title": suspect.title,
                        "description": suspect.description,
                        "confidence": suspect.confidence,
                        "severity": suspect.severity.value,
                        "evidence": suspect.evidence,
                        "suggested_actions": suspect.suggested_actions,
                        "metadata": suspect.metadata
                    }
                    for suspect in state["suspects"]
                ],
                "historical_context": state.get("historical_context", []),
                "historical_context_count": len(state.get("historical_context", [])),
                "rca_result": state.get("rca_result"),
                "rca_completed": state.get("rca_result") is not None,
                "timestamp": datetime.utcnow().isoformat(),
                "environment": os.getenv("ENVIRONMENT", "development")
            }
            
            # Send comprehensive message
            message_body = json.dumps(comprehensive_message, default=str)
            
            response = self.sqs_client.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=message_body,
                MessageAttributes={
                    'incident_id': {
                        'StringValue': state["incident_id"],
                        'DataType': 'String'
                    },
                    'message_type': {
                        'StringValue': 'SUSPECT_GENERATION_COMPLETE',
                        'DataType': 'String'
                    },
                    'suspects_count': {
                        'StringValue': str(len(state["suspects"])),
                        'DataType': 'Number'
                    },
                    'rca_completed': {
                        'StringValue': str(state.get("rca_result") is not None),
                        'DataType': 'String'
                    },
                    'environment': {
                        'StringValue': os.getenv("ENVIRONMENT", "development"),
                        'DataType': 'String'
                    }
                }
            )
            
            logger.info(f"Successfully sent comprehensive analysis results to SQS: {response['MessageId']}")
            
        except Exception as e:
            logger.error(f"Error sending analysis results to SQS: {e}")
        
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
            historical_context=[],
            rca_result=None,
            alert_data=request.context.get("alert_data", {}),
            telemetry=request.context.get("telemetry", {}),
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
