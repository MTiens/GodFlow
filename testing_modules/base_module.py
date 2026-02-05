# testing_modules/base_module.py

from abc import ABC, abstractmethod
from typing import List, NamedTuple, Optional, Dict, Any, Union
import re
from core.runner import RequestRunner
from core.state import StateManager
from core.payload import PayloadManager

# A standardized way to report findings
class FuzzingResult(NamedTuple):
    is_vulnerable: bool
    description: str
    request: dict
    response_status: int
    response_size: int
    payload: str = ""
    baseline_comparison: Optional[Dict[str, Any]] = None  # New field for baseline analysis
    anomaly_details: Optional[List[Dict[str, Any]]] = None  # Detailed anomaly information
    x_trace_id: str = ""  # X-Trace-Id header value for tracking requests

class FuzzingModule(ABC):
    """Abstract Base Class for all fuzzing/testing modules."""
    
    # A unique key used in the flow.json to invoke this module
    key = "base"
    
    def __init__(self, runner: RequestRunner, state_manager: StateManager, payload_manager: PayloadManager, **kwargs):
        self.runner = runner
        self.state_manager = state_manager
        self.payload_manager = payload_manager
        self.kwargs = kwargs
        self.baseline_manager = None  # Will be injected by orchestrator if available
        self.baseline_collection = None  # Will be loaded if baseline comparison is enabled
    
    def set_baseline_context(self, baseline_manager, baseline_collection):
        """Set baseline context for enhanced vulnerability detection."""
        self.baseline_manager = baseline_manager
        self.baseline_collection = baseline_collection
    
    def check_custom_matchers(self, response, matchers: List[Dict[str, Any]]) -> bool:
        """
        Check response against user-defined matchers from YAML configuration.
        
        Matcher types:
        - status: Match HTTP status codes. value: [200, 201] or single int.
        - word: Match literal words in body/headers. words: ["error", "sql"]
        - regex: Match regex pattern in body/headers. pattern: "error.*"
        
        Options:
        - part: "body" | "header" | "all" (default: "body" for word/regex, N/A for status)
        - condition: "and" | "or" (default: "or" - any matcher triggers)
        - negative: true to invert match result
        
        Args:
            response: The HTTP response object
            matchers: List of matcher configurations
            
        Returns:
            True if matchers indicate vulnerability, False otherwise.

        fuzz:
          flow_fuzzer:
              enable: true
              matchers:
                - type: status
                value: [500, 503]
                - type: word
                part: body
                words: ["SQL syntax", "internal error"]
                condition: or
                - type: regex
                pattern: "exception.*at line"
                negative: true
        """
        if not matchers:
            return False
        
        # Get condition for combining matcher results (default: or)
        global_condition = "or"  # Default: any matcher triggers
        
        matcher_results = []
        
        for matcher in matchers:
            matcher_type = matcher.get("type", "status")
            negative = matcher.get("negative", False)
            result = False
            
            if matcher_type == "status":
                # Status code matching
                values = matcher.get("value", matcher.get("values", []))
                if isinstance(values, int):
                    values = [values]
                result = response.status_code in values
                
            elif matcher_type == "word":
                # Word matching in body/headers
                words = matcher.get("words", [])
                part = matcher.get("part", "body")
                word_condition = matcher.get("condition", "or")
                
                text = self._get_response_part(response, part)
                
                if word_condition == "and":
                    result = all(word.lower() in text.lower() for word in words)
                else:  # or
                    result = any(word.lower() in text.lower() for word in words)
                    
            elif matcher_type == "regex":
                # Regex matching
                pattern = matcher.get("pattern", "")
                part = matcher.get("part", "body")
                
                text = self._get_response_part(response, part)
                
                try:
                    result = bool(re.search(pattern, text, re.IGNORECASE))
                except re.error:
                    result = False
            
            # Apply negative (invert)
            if negative:
                result = not result
                
            matcher_results.append(result)
        
        # Combine results based on global condition
        if global_condition == "and":
            return all(matcher_results)
        else:  # or
            return any(matcher_results)
    
    def _get_response_part(self, response, part: str) -> str:
        """Extract specified part of response for matching."""
        if part == "body":
            return getattr(response, 'text', '')
        elif part == "header":
            headers = getattr(response, 'headers', {})
            return ' '.join(f"{k}: {v}" for k, v in headers.items())
        else:  # all
            body = getattr(response, 'text', '')
            headers = getattr(response, 'headers', {})
            header_text = ' '.join(f"{k}: {v}" for k, v in headers.items())
            return f"{header_text} {body}"
    
    def enhance_result_with_baseline(self, result: FuzzingResult) -> FuzzingResult:
        """
        Enhance a FuzzingResult with baseline comparison information.
        
        This function extracts the repeated baseline comparison logic that appears
        in all testing modules and provides a centralized way to enhance results
        with baseline analysis information.
        
        Args:
            result: The FuzzingResult to enhance
            
        Returns:
            Enhanced FuzzingResult with baseline information added to description
        """
        if not result.baseline_comparison or not result.baseline_comparison.get("baseline_available"):
            return result
            
        anomalies = result.anomaly_details or []
        anomaly_types = [a.get("type") for a in anomalies]
        confidence = result.baseline_comparison.get("confidence", 0.0)
        enhanced_description = result.description
        
        # Add baseline insights to the description
        if "unexpected_status_code" in anomaly_types:
            enhanced_description += f" (Status anomaly detected with {confidence:.1%} confidence)"
        if "unexpected_response_size" in anomaly_types:
            enhanced_description += f" (Response size anomaly with {confidence:.1%} confidence)"
        if "missing_response_patterns" in anomaly_types:
            enhanced_description += f" (Response pattern disruption with {confidence:.1%} confidence)"
        if "missing_critical_header" in anomaly_types:
            enhanced_description += f" (Missing security headers with {confidence:.1%} confidence)"
        if "unexpected_response_patterns" in anomaly_types:
            enhanced_description += f" (Response pattern anomaly with {confidence:.1%} confidence)"
            
        return result._replace(description=enhanced_description)
    
    def analyze_response_with_baseline(self, step_name: str, request: dict, response, 
                                     expected_vulnerable: bool = False) -> Dict[str, Any]:
        """
        Analyze a response using baseline comparison for enhanced vulnerability detection.
        
        Args:
            step_name: Name of the current step
            request: The request that was sent
            response: The response received
            expected_vulnerable: Whether we expect this response to be vulnerable
            
        Returns:
            Dictionary containing baseline analysis results
        """
        if not self.baseline_manager or not self.baseline_collection:
            return {"baseline_available": False, "analysis": "No baseline available"}
            
        comparison = self.baseline_manager.compare_response(
            step_name, request, response, self.baseline_collection
        )
        
        # Enhanced vulnerability analysis using baseline
        is_vulnerable_by_baseline = self._assess_vulnerability_from_baseline(
            comparison, expected_vulnerable
        )
        
        return {
            "baseline_available": True,
            "comparison": comparison,
            "is_vulnerable_by_baseline": is_vulnerable_by_baseline,
            "confidence": self._calculate_confidence(comparison)
        }
    
    def _assess_vulnerability_from_baseline(self, comparison: Dict[str, Any], 
                                          expected_vulnerable: bool) -> bool:
        """
        Assess if a response indicates vulnerability based on baseline comparison.
        
        This provides a much more intelligent assessment than hardcoded rules.
        """
        if not comparison.get("has_baseline"):
            return False  # Can't assess without baseline
            
        anomalies = comparison.get("anomalies", [])
        risk_level = comparison.get("risk_level", "none")
        
        # If we expect this to be vulnerable (e.g., testing with attack payloads)
        # then significant anomalies might indicate successful exploitation
        if expected_vulnerable:
            # High risk anomalies strongly suggest vulnerability
            if risk_level in ["high"]:
                return True
                
            # Check for specific anomaly types that suggest successful attacks
            for anomaly in anomalies:
                anomaly_type = anomaly.get("type")
                severity = anomaly.get("severity", "low")
                
                # Status code changes often indicate successful attacks
                if anomaly_type == "unexpected_status_code" and severity in ["high", "medium"]:
                    return True
                    
                # Significant response size changes might indicate data exposure/injection
                if anomaly_type == "unexpected_response_size" and severity in ["high", "medium"]:
                    actual = anomaly.get("actual", 0)
                    expected_range = anomaly.get("expected_range", [0, 0])
                    # If response is much larger, might indicate data leakage
                    if actual > expected_range[1] * 2:
                        return True
                        
                # Missing security headers in attack scenarios
                if anomaly_type == "missing_critical_header" and severity == "medium":
                    header = anomaly.get("header", "")
                    if header in ["x-frame-options", "content-security-policy"]:
                        return True
        
        # If we don't expect vulnerability but see high-risk anomalies,
        # it might indicate an unexpected security issue
        elif risk_level == "high":
            return True
            
        return False
    
    def _calculate_confidence(self, comparison: Dict[str, Any]) -> float:
        """Calculate confidence level of the vulnerability assessment (0.0 to 1.0)."""
        if not comparison.get("has_baseline"):
            return 0.0
            
        baseline_success_count = comparison.get("baseline_success_count", 0)
        risk_level = comparison.get("risk_level", "none")
        anomaly_count = len(comparison.get("anomalies", []))
        
        # Base confidence on baseline quality
        baseline_confidence = min(1.0, baseline_success_count / 10.0)  # Max confidence with 10+ samples
        
        # Adjust based on anomaly severity
        risk_multipliers = {"none": 0.1, "low": 0.3, "medium": 0.7, "high": 1.0}
        risk_confidence = risk_multipliers.get(risk_level, 0.5)
        
        # Combine factors
        # overall_confidence = (baseline_confidence * 0.6) + (risk_confidence * 0.4)
        overall_confidence = baseline_confidence
        
        return min(1.0, overall_confidence)
    
    def create_enhanced_result(self, is_vulnerable: bool, description: str, request: dict, 
                             response, payload: str = "", step_name: str = "", 
                             expected_vulnerable: bool = False) -> FuzzingResult:
        """
        Create a FuzzingResult with enhanced baseline analysis if available.
        
        This method should be used instead of directly creating FuzzingResult objects
        to get the benefit of baseline comparison.
        """
        response_status = getattr(response, 'status_code', 0)
        response_size = len(getattr(response, 'content', b''))
        
        # Perform baseline analysis if available
        baseline_analysis = None
        anomaly_details = None
        
        if step_name and self.baseline_manager and self.baseline_collection:
            baseline_analysis = self.analyze_response_with_baseline(
                step_name, request, response, expected_vulnerable
            )
            
            if baseline_analysis.get("baseline_available"):
                comparison = baseline_analysis.get("comparison", {})
                anomaly_details = comparison.get("anomalies", [])
                
                # Override vulnerability assessment if baseline provides higher confidence
                baseline_vulnerable = baseline_analysis.get("is_vulnerable_by_baseline", False)
                confidence = baseline_analysis.get("confidence", 0.0)
                
                if confidence > 0.7:  # High confidence threshold
                    is_vulnerable = baseline_vulnerable
                    
                    # Update description with baseline insights
                    if baseline_vulnerable and not is_vulnerable:
                        description += f" (Baseline analysis indicates vulnerability with {confidence:.1%} confidence)"
                    elif not baseline_vulnerable and is_vulnerable:
                        description += f" (Baseline analysis suggests false positive with {confidence:.1%} confidence)"
        
        # Extract X-Trace-Id from request headers (since we send it in the request)
        x_trace_id = ""
        if hasattr(request, 'get') and request.get('headers'):
            x_trace_id = request.get('headers', {}).get('X-Trace-Id', '')
        
        result = FuzzingResult(
            is_vulnerable=is_vulnerable,
            description=description,
            request=request,
            response_status=response_status,
            response_size=response_size,
            payload=payload,
            baseline_comparison=baseline_analysis,
            anomaly_details=anomaly_details,
            x_trace_id=x_trace_id
        )
        
        return self.enhance_result_with_baseline(result)
    
    async def prepare(self, step_config: dict, flow_context: dict) -> bool:
        """
        Lifecycle hook to prepare the module for execution.
        
        This method is called before run(). It can be used to:
        - Validate configuration
        - Establish necessary state (e.g., login multiple personas)
        - Perform any setup steps
        
        Args:
            step_config: The configuration for this step from the flow file.
            flow_context: Context about the overall flow (requests_dir, target, steps, etc.)
            
        Returns:
            bool: True if preparation was successful and module should run.
                  False if module should be skipped.
        """
        return True

    @abstractmethod
    def run(self, parsed_request: dict, step_config: dict, **kwargs) -> List[FuzzingResult]:
        """
        The main execution method for the module.
        It receives the parsed request for the step and the step's configuration.
        It must return a list of FuzzingResult objects.
        """
        pass