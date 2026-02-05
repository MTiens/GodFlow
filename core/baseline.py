import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
import httpx
from datetime import datetime
from core.colors import format_log_prefix, color_formatter


@dataclass
class ResponseBaseline:
    """Represents a baseline expectation for an API endpoint response."""
    endpoint_id: str  # Unique identifier for the endpoint
    method: str
    url_pattern: str  # URL with placeholders like /api/users/{user_id}
    expected_status_codes: Set[int]
    expected_headers: Dict[str, str]  # Critical headers that should be present
    response_size_range: tuple  # (min_size, max_size) in bytes
    response_patterns: List[str]  # Key patterns that should appear in successful responses
    content_type_patterns: List[str]  # Expected content types
    created_at: str
    success_count: int = 0  # Number of successful responses used to build this baseline


@dataclass 
class BaselineCollection:
    """Collection of baselines for a project/flow."""
    project_name: str
    flow_name: str
    baselines: Dict[str, ResponseBaseline]
    created_at: str
    last_updated: str


class BaselineManager:
    """Manages collection, storage, and comparison of API response baselines."""
    
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.baselines_dir = self.project_dir / "baselines"
        self.baselines_dir.mkdir(exist_ok=True)
        self.current_collection: Optional[BaselineCollection] = None
        
    def start_collection(self, project_name: str, flow_name: str) -> None:
        """Start a new baseline collection session."""
        self.current_collection = BaselineCollection(
            project_name=project_name,
            flow_name=flow_name,
            baselines={},
            created_at=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat()
        )
        print(format_log_prefix("BASELINE", f"Started collecting baselines for {project_name}/{flow_name}"))
    
    def record_response(self, step_name: str, request: Dict[str, Any], 
                       response: httpx.Response, is_successful: bool = True) -> None:
        """Record a response as part of the baseline collection."""
        if not self.current_collection:
            return
            
        if not is_successful:
            return  # Only record successful responses for baselines
            
        endpoint_id = self._generate_endpoint_id(step_name, request)
        url_pattern = self._extract_url_pattern(request.get('url', ''))
        
        # Extract key response characteristics
        response_size = len(response.content) if response.content else 0
        response_patterns = self._extract_response_patterns(response)
        content_types = [response.headers.get('content-type', '').split(';')[0]]
        
        # Check if we already have a baseline for this endpoint
        if endpoint_id in self.current_collection.baselines:
            baseline = self.current_collection.baselines[endpoint_id]
            # Update existing baseline with new data
            baseline.expected_status_codes.add(response.status_code)
            baseline.response_size_range = (
                min(baseline.response_size_range[0], response_size),
                max(baseline.response_size_range[1], response_size)
            )
            baseline.response_patterns = list(set(baseline.response_patterns + response_patterns))
            baseline.content_type_patterns = list(set(baseline.content_type_patterns + content_types))
            baseline.success_count += 1
        else:
            # Create new baseline
            critical_headers = self._extract_critical_headers(response)
            baseline = ResponseBaseline(
                endpoint_id=endpoint_id,
                method=request.get('method', 'GET'),
                url_pattern=url_pattern,
                expected_status_codes={response.status_code},
                expected_headers=critical_headers,
                response_size_range=(response_size, response_size),
                response_patterns=response_patterns,
                content_type_patterns=content_types,
                created_at=datetime.now().isoformat(),
                success_count=1
            )
            self.current_collection.baselines[endpoint_id] = baseline
            
        status_colored = color_formatter.status_code(response.status_code)
        print(format_log_prefix("BASELINE", f"Recorded response for {endpoint_id}: {status_colored} ({response_size} bytes)"))
    
    def save_collection(self, filename: Optional[str] = None) -> str:
        """Save the current baseline collection to disk."""
        if not self.current_collection:
            raise ValueError("No active baseline collection to save")
            
        if not filename:
            filename = f"{self.current_collection.project_name}_{self.current_collection.flow_name}_baselines.json"
            
        filepath = self.baselines_dir / filename
        
        # Convert to serializable format
        serializable_data = {
            "project_name": self.current_collection.project_name,
            "flow_name": self.current_collection.flow_name,
            "created_at": self.current_collection.created_at,
            "last_updated": datetime.now().isoformat(),
            "baselines": {}
        }
        
        for endpoint_id, baseline in self.current_collection.baselines.items():
            baseline_dict = asdict(baseline)
            # Convert set to list for JSON serialization
            baseline_dict["expected_status_codes"] = list(baseline.expected_status_codes)
            serializable_data["baselines"][endpoint_id] = baseline_dict
            
        with open(filepath, 'w') as f:
            json.dump(serializable_data, f, indent=2)
            
        print(format_log_prefix("BASELINE", f"Saved {len(self.current_collection.baselines)} baselines to {filepath}"))
        return str(filepath)
    
    def load_collection(self, filename: str) -> BaselineCollection:
        """Load a baseline collection from disk."""
        filepath = self.baselines_dir / filename
        
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        baselines = {}
        for endpoint_id, baseline_data in data["baselines"].items():
            # Convert list back to set
            baseline_data["expected_status_codes"] = set(baseline_data["expected_status_codes"])
            baselines[endpoint_id] = ResponseBaseline(**baseline_data)
            
        collection = BaselineCollection(
            project_name=data["project_name"],
            flow_name=data["flow_name"],
            baselines=baselines,
            created_at=data["created_at"],
            last_updated=data["last_updated"]
        )
        
        print(format_log_prefix("BASELINE", f"Loaded {len(baselines)} baselines from {filepath}"))
        return collection
    
    def compare_response(self, step_name: str, request: Dict[str, Any], 
                        response: httpx.Response, baseline_collection: BaselineCollection) -> Dict[str, Any]:
        """Compare a response against established baselines to detect anomalies."""
        endpoint_id = self._generate_endpoint_id(step_name, request)
        
        if endpoint_id not in baseline_collection.baselines:
            return {
                "has_baseline": False,
                "anomalies": [],
                "risk_level": "unknown",
                "message": f"No baseline found for endpoint {endpoint_id}"
            }
            
        baseline = baseline_collection.baselines[endpoint_id]
        anomalies = []
        
        # Check status code
        if response.status_code not in baseline.expected_status_codes:
            anomalies.append({
                "type": "unexpected_status_code",
                "expected": list(baseline.expected_status_codes),
                "actual": response.status_code,
                "severity": "high" if response.status_code >= 500 else "medium"
            })
            
        # Check response size
        response_size = len(response.content) if response.content else 0
        min_size, max_size = baseline.response_size_range
        size_tolerance = max(500, max_size * 0.2)  # 20% tolerance or 500 bytes minimum
        
        if response_size < (min_size - size_tolerance) or response_size > (max_size + size_tolerance):
            anomalies.append({
                "type": "unexpected_response_size",
                "expected_range": [min_size, max_size],
                "actual": response_size,
                "severity": "medium" if abs(response_size - max_size) > max_size else "low"
            })
            
        # Check content type
        actual_content_type = response.headers.get('content-type', '').split(';')[0]
        if actual_content_type and actual_content_type not in baseline.content_type_patterns:
            anomalies.append({
                "type": "unexpected_content_type",
                "expected": baseline.content_type_patterns,
                "actual": actual_content_type,
                "severity": "medium"
            })
            
        # Check for missing critical headers
        for header, expected_value in baseline.expected_headers.items():
            actual_value = response.headers.get(header)
            if not actual_value:
                anomalies.append({
                    "type": "missing_critical_header",
                    "header": header,
                    "expected": expected_value,
                    "severity": "medium"
                })
                
        # Check response patterns
        response_text = response.text if hasattr(response, 'text') else str(response.content)
        missing_patterns = []
        for pattern in baseline.response_patterns:
            if pattern not in response_text:
                missing_patterns.append(pattern)
                
        if missing_patterns:
            anomalies.append({
                "type": "missing_response_patterns",
                "missing_patterns": missing_patterns,
                "severity": "low"
            })
        
        # Calculate overall risk level
        risk_level = self._calculate_risk_level(anomalies)
        
        return {
            "has_baseline": True,
            "endpoint_id": endpoint_id,
            "anomalies": anomalies,
            "risk_level": risk_level,
            "baseline_success_count": baseline.success_count,
            "message": f"Found {len(anomalies)} anomalies" if anomalies else "Response matches baseline"
        }
    
    def _generate_endpoint_id(self, step_name: str, request: Dict[str, Any]) -> str:
        """Generate a unique identifier for an endpoint."""
        method = request.get('method', 'GET')
        url = request.get('url', '')
        url_pattern = self._extract_url_pattern(url)
        
        # Create a hash of the method + url pattern + step name
        identifier = f"{method}:{url_pattern}:{step_name}"
        return hashlib.md5(identifier.encode()).hexdigest()[:12]
    
    def _extract_url_pattern(self, url: str) -> str:
        """Extract URL pattern by replacing dynamic segments with placeholders."""
        import re
        
        # Replace numeric IDs with placeholder
        url = re.sub(r'/\d+(?=/|$)', '/{id}', url)
        
        # Replace UUIDs with placeholder
        url = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=/|$)', '/{uuid}', url)
        
        # Replace other dynamic segments (simple heuristic)
        url = re.sub(r'/[^/]{20,}(?=/|$)', '/{dynamic}', url)
        
        return url
    
    def _extract_response_patterns(self, response: httpx.Response) -> List[str]:
        """Extract key patterns from successful response that indicate normal behavior."""
        patterns = []
        
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                json_data = response.json()
                # Extract top-level keys as patterns
                if isinstance(json_data, dict):
                    patterns.extend([f'"${key}"' for key in json_data.keys() if len(key) < 50])
                    
                    # Look for success indicators
                    success_indicators = ['success', 'status', 'ok', 'result', 'data']
                    for indicator in success_indicators:
                        if indicator in json_data:
                            patterns.append(f'"${indicator}":')
            else:
                # For non-JSON, look for common HTML/text patterns
                text = response.text[:1000]  # First 1000 chars
                
                # HTML patterns
                if '<html' in text.lower():
                    patterns.append('<html')
                if '<title>' in text.lower():
                    patterns.append('<title>')
                    
                # Look for success indicators in text
                success_words = ['success', 'welcome', 'dashboard', 'profile']
                for word in success_words:
                    if word.lower() in text.lower():
                        patterns.append(word.lower())
                        
        except Exception:
            pass  # Ignore parsing errors
            
        return patterns[:10]  # Limit to top 10 patterns
    
    def _extract_critical_headers(self, response: httpx.Response) -> Dict[str, str]:
        """Extract headers that are critical for security/functionality."""
        critical_header_names = [
            'content-type',
            'cache-control', 
            'x-frame-options',
            'x-content-type-options',
            'strict-transport-security',
            'content-security-policy'
        ]
        
        critical_headers = {}
        for header in critical_header_names:
            value = response.headers.get(header)
            if value:
                critical_headers[header] = value
                
        return critical_headers
    
    def _calculate_risk_level(self, anomalies: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on anomalies."""
        if not anomalies:
            return "none"
            
        high_count = sum(1 for a in anomalies if a.get('severity') == 'high')
        medium_count = sum(1 for a in anomalies if a.get('severity') == 'medium')
        
        if high_count > 0:
            return "high"
        elif medium_count > 2:
            return "high"
        elif medium_count > 0:
            return "medium"
        else:
            return "low"

    def list_available_baselines(self) -> List[str]:
        """List all available baseline files."""
        return [f.name for f in self.baselines_dir.glob("*.json")] 