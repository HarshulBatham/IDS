import logging
from typing import Dict, Optional
import google.generativeai as genai

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMIntegrator:
    """Handles cloud Gemini LLM integration for network anomaly analysis."""
    
    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash"):
        """Initialize the Gemini API."""
        self.api_key = api_key
        self.model_name = model_name
        
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            logger.error("Gemini API key is missing or invalid!")
            self.model = None
        else:
            # Tell Pylance to ignore the library's internal export structure
            genai.configure(api_key=self.api_key) # type: ignore
            self.model = genai.GenerativeModel(self.model_name) # type: ignore

    def query_gemini(self, prompt: str) -> Optional[str]:
        """Query Google Gemini API for cloud-based LLM analysis."""
        if not self.model:
            return "⚠️ Error: Gemini API key not configured properly."
            
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig( # type: ignore
                    temperature=0.3, # Low temperature for more factual, less creative responses
                    max_output_tokens=1024,
                )
            )
            return response.text.strip()
            
        except Exception as e:
            logger.error(f"Gemini query error: {e}")
            return f"⚠️ Error contacting Gemini API: {str(e)}"
    
    def analyze_anomaly(self, flow_data: Dict) -> str:
        """
        Generate root cause analysis for detected anomaly.
        """
        prompt = self._build_analysis_prompt(flow_data)
        result = self.query_gemini(prompt)
        
        # FIXED: Ensure we always return a string, even if query_gemini returns None
        return result if result is not None else "⚠️ Error: Failed to generate analysis from LLM."
    
    def _build_analysis_prompt(self, flow_data: Dict) -> str:
        """Build a structured prompt for anomaly analysis."""
        prompt = f"""Analyze this network anomaly and provide root cause analysis:

Flow Data:
- Source IP: {flow_data.get('src_ip', 'N/A')}
- Destination IP: {flow_data.get('dst_ip', 'N/A')}
- Source Port: {flow_data.get('src_port', 'N/A')}
- Destination Port: {flow_data.get('dst_port', 'N/A')}
- Protocol: {flow_data.get('protocol', 'N/A')}
- Application: {flow_data.get('application_name', 'N/A')}
- Local Process: {flow_data.get('Process_Name', 'N/A')} (PID: {flow_data.get('Local_PID', 'N/A')})
- Duration: {flow_data.get('bidirectional_duration_ms', 0)}ms
- Bytes Transferred: {flow_data.get('bidirectional_bytes', 0)}

Provide:
1. Threat Assessment (Low/Medium/High)
2. Likely Cause (2-3 sentences)
3. Recommended Action (1-2 sentences)
4. False Positive Risk (Low/Medium/High) if applicable

Be concise and technical."""
        
        return prompt