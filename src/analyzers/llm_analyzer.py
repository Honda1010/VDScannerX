import openai

class LLMAnalyzer:
    def __init__(self, api_key):
        openai.api_key = api_key
        
    def generate_threat_analysis(self, analysis_data):
        """Generate natural language analysis of threat data"""
        prompt = self._create_analysis_prompt(analysis_data)
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing malware behavior."},
                {"role": "user", "content": prompt}
            ]
        )
        
        return response.choices[0].message.content
        
    def _create_analysis_prompt(self, analysis_data):
        # Create a detailed prompt with the analysis data
        prompt = "Based on the following malware analysis results, provide a detailed threat assessment:\n\n"
        
        # Add behavior data
        if 'processes' in analysis_data:
            prompt += "Process Activity:\n"
            for process in analysis_data['processes'][:5]:  # Limit to first 5 processes
                prompt += f"- {process.get('name', 'Unknown')}\n"
        
        # Add network data
        if 'network_communications' in analysis_data:
            prompt += "\nNetwork Activity:\n"
            for comm in analysis_data['network_communications'][:5]:
                prompt += f"- {comm.get('protocol', 'Unknown')} connection to {comm.get('remote_address', 'Unknown')}\n"
        
        # Add MITRE ATT&CK techniques
        if 'mitre_attacks' in analysis_data:
            prompt += "\nMITRE ATT&CK Techniques:\n"
            for attack in analysis_data['mitre_attacks'][:5]:
                prompt += f"- {attack.get('id', 'Unknown')}: {attack.get('signature_description', 'Unknown')}\n"
        
        prompt += "\nPlease provide:\n"
        prompt += "1. A threat assessment summary\n"
        prompt += "2. The likely classification of this malware\n"
        prompt += "3. Recommendations for mitigation\n"
        prompt += "4. Risk level (Low, Medium, High, Critical)"
        
        return prompt
