import requests
import json
import streamlit as st
from typing import Dict, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMIntegrator:
    """Handles both local Ollama and cloud Gemini LLM integrations."""
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize LLM provider based on config."""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Config file {config_file} not found!")
            self.config = {}
        
        self.mode = self.config.get("llm_config", {}).get("mode", "local")
        self.local_config = self.config.get("llm_config", {}).get("local", {})
        self.gemini_config = self.config.get("llm_config", {}).get("gemini", {})
    
    def query_local_ollama(self, prompt: str) -> Optional[str]:
        """Query local Ollama instance with phi4-mini model."""
        try:
            ollama_url = self.local_config.get("ollama_url", "http://localhost:11434")
            model = self.local_config.get("model", "phi4-mini:3.8b-q4_K_M")
            
            response = requests.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": self.local_config.get("temperature", 0.3),
                    "top_p": self.local_config.get("top_p", 0.9)
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "No response received").strip()
            else:
                logger.error(f"Ollama error: {response.status_code}")
                return None
                
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama. Ensure it's running: ollama serve")
            return None
        except Exception as e:
            logger.error(f"Ollama query error: {e}")
            return None
    
    def query_gemini(self, prompt: str) -> Optional[str]:
        """Query Google Gemini API for cloud-based LLM analysis."""
        try:
            api_key = self.gemini_config.get("api_key")
            if not api_key or api_key == "YOUR_GEMINI_API_KEY_HERE":
                logger.error("Gemini API key not configured")
                return None
            
            import google.generativeai as genai  # Lazy import
            
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(self.gemini_config.get("model", "gemini-1.5-pro"))
            
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=1024,
                )
            )
            
            return response.text.strip()
            
        except ImportError:
            logger.error("Google Generative AI library not installed. Install with: pip install google-generativeai")
            return None
        except Exception as e:
            logger.error(f"Gemini query error: {e}")
            return None
    
    def analyze_anomaly(self, flow_data: Dict) -> str:
        """
        Generate root cause analysis for detected anomaly.
        Returns analysis text using configured LLM mode.
        """
        prompt = self._build_analysis_prompt(flow_data)
        
        if self.mode == "local":
            result = self.query_local_ollama(prompt)
        elif self.mode == "gemini":
            result = self.query_gemini(prompt)
        else:
            logger.warning(f"Unknown LLM mode: {self.mode}")
            result = None
        
        return result or "⚠️ LLM analysis unavailable. Check configuration."
    
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