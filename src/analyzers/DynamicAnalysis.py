import requests
import time
import json
import os
from config import Config
from src.utils.json_saver import JSONSaver

class DynamicAnalyzer:
    def __init__(self):
        self.API_KEY = Config.HYBRID_ANALYSIS_API_KEY
        self.VT_API_KEY = Config.VT_DYNAMIC_API_KEY  # Use the dedicated VT key
        self.HEADERS = {
            'api-key': self.API_KEY,
            'User-Agent': 'VxApi Client'
        }
        # VirusTotal specific headers
        self.VT_HEADERS = {
            'x-apikey': self.VT_API_KEY,
            'User-Agent': 'VDScannerX-Client'
        }
        self.VT_BASE_URL = "https://www.virustotal.com/api/v3"

    def submit_file(self, file_path):
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            data = {'environment_id': '120'} 
            response = requests.post(
                'https://www.hybrid-analysis.com/api/v2/submit/file',
                headers=self.HEADERS, files=files, data=data
            )

        try:
            json_data = response.json()
            if response.status_code == 200:
                JSONSaver.save_api_response(json_data, 'hybrid_analysis_submit')
        except Exception:
            raise Exception(f"Failed to parse response: {response.text}")

        job_id = json_data.get("job_id")
        if job_id:
            print(f"Submission successful. Job ID: {job_id}")
            return job_id
        else:
            raise Exception(f"Submission failed: {json_data}")

    def fetch_report(self, job_id):
        print("Waiting for full report...")
        max_attempts = 30  # Increase max attempts (150 seconds total)
        for attempt in range(max_attempts):
            try:
                # First check the analysis state
                state_url = f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/state'
                state_response = requests.get(state_url, headers=self.HEADERS)
                if state_response.status_code == 200:
                    state_data = state_response.json()
                    if state_data.get("state") == "ERROR":
                        raise Exception("Analysis failed: " + state_data.get("error", "Unknown error"))
                    
                    # If analysis is complete, get the full report
                    if state_data.get("state") == "SUCCESS":
                        report_url = f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary'
                        report_response = requests.get(report_url, headers=self.HEADERS)
                        if report_response.status_code == 200:
                            try:
                                json_data = report_response.json()
                                # Save the successful report
                                JSONSaver.save_api_response(json_data, 'hybrid_analysis_report')
                                return json_data
                            except Exception as e:
                                print(f"Error parsing report (attempt {attempt + 1}): {str(e)}")
                                continue
                
                # If we're here, either the analysis is still running or we got an unexpected response
                remaining = max_attempts - attempt - 1
                print(f"Analysis in progress... {remaining} attempts remaining")
                time.sleep(5)
                
            except Exception as e:
                print(f"Error checking status (attempt {attempt + 1}): {str(e)}")
                time.sleep(5)
                continue

        raise Exception("Report not ready after waiting. The analysis might need more time or there might be an issue with the service.")

    def analyze_file(self, file_path):
        try:
            job_id = self.submit_file(file_path)
            report_data = self.fetch_report(job_id)
            
            # Process and structure the report data
            analysis_results = {
                'basic_info': {
                    'Verdict': report_data.get('verdict', 'Unknown'),
                    'Sample Name': report_data.get('submit_name', 'Unknown'),
                    'File Type': report_data.get('type', 'Unknown'),
                    'SHA256': report_data.get('sha256', 'Unknown'),
                    'Size': report_data.get('size', 'Unknown'),
                    'Environment': report_data.get('environment_description', 'Unknown'),
                    'Threat Score': report_data.get('threat_score', 'Unknown')
                },
                'signatures': [
                    {
                        'name': sig.get('name', 'Unknown'),
                        'description': sig.get('description', ''),
                        'threat_level': sig.get('threat_level', 'Unknown'),
                        'threat_level_human': sig.get('threat_level_human', 'Unknown'),
                        'category': sig.get('category', 'Uncategorized')
                    }
                    for sig in report_data.get('signatures', [])
                ],
                'processes': [
                    {
                        'uid': proc.get('uid','Unknown'),
                        'parentuid': proc.get('parentuid','Unknown'),
                        'name': proc.get('name','Unknown'),
                        'normalized_path': proc.get('normalized_path','Unknown'),
                        'command_line': proc.get('command_line','Unknown'),
                        'sha256': proc.get('sha256','Unknown'),
                        'av_label': proc.get('av_label','Unknown'),
                        'av_matched': proc.get('av_matched','Unknown'),
                        'av_total': proc.get('av_total','Unknown'),
                        'pid': proc.get('pid','Unknown'),
                        'icon': proc.get('icon','Unknown'),
                        'file_accesses': proc.get('file_accesses','Unknown'),
                        'created_files': proc.get('created_files','Unknown'),
                        'registry': proc.get('registry','Unknown'),
                        'mutants': proc.get('mutants','Unknown'),
                        'handles': proc.get('handles','Unknown'),
                        'streams': proc.get('streams','Unknown'),
                        'script_calls': proc.get('script_calls','Unknown'),
                        'process_flags': proc.get('process_flags','Unknown'),
                        'amsi_calls': proc.get('amsi_calls','Unknown'),
                        'modules': proc.get('modules','Unknown')
                    }
                    for proc in report_data.get('processes', [])
                ],    
                'extracted_urls': report_data.get('extracted_urls', []),
                'mitre_attacks': [
                    {
                        'tactic': attack.get('tactic'),
                        'technique': attack.get('technique'),
                        'attck_id': attack.get('attck_id'),
                        'attck_id_wiki': attack.get('attck_id_wiki'),
                        'malicious_identifiers_count': attack.get('malicious_identifiers_count', 0),
                        'suspicious_identifiers_count': attack.get('suspicious_identifiers_count', 0),
                        'informative_identifiers_count': attack.get('informative_identifiers_count', 0),
                        'description': attack.get('description'),
                    }
                    for attack in report_data.get('mitre_attcks', [])
                ],
                'dropped_files': [
                    {
                        'name': file.get('name'),
                        'file_path': file.get('file_path'),
                        'file_size': file.get('file_size'),
                        'type': file.get('description'),
                        'sha256': file.get('sha256'),
                        'threat_level_readable': file.get('threat_level_readable'),
                    }
                    for file in report_data.get('extracted_files', [])
                ],
                'interesting_behaviors': report_data.get('interesting', {}) if isinstance(report_data.get('interesting'), dict) else {}
            }
            
            return {
                'success': True,
                'data': analysis_results
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def submit_file_to_vt(self, file_path):
        """Submit a file to VirusTotal for analysis"""
        # Prepare the file for upload
        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            url = f"{self.VT_BASE_URL}/files"
            
            print("Uploading file to VirusTotal...")
            
            response = requests.post(url, headers=self.VT_HEADERS, files=files)
            
            if response.status_code == 200:
                json_response = response.json()
                JSONSaver.save_api_response(json_response, 'virustotal_upload')
                
                # The API might return data directly or an analysis ID
                if 'data' in json_response:
                    if 'id' in json_response['data']:
                        analysis_id = json_response['data']['id']
                    else:
                        analysis_id = None
                    
                    # Get the file hash from either direct response or attributes
                    if 'attributes' in json_response['data'] and 'sha256' in json_response['data']['attributes']:
                        file_hash = json_response['data']['attributes']['sha256']
                    elif 'sha256' in json_response['data']:
                        file_hash = json_response['data']['sha256']
                    else:
                        # If hash not in response, compute it
                        import hashlib
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    return {'analysis_id': analysis_id, 'file_hash': file_hash}
            
            # If we reach here, something went wrong
            error_msg = f"Error uploading file: Status code {response.status_code}"
            if response.text:
                error_msg += f" - {response.text}"
            raise Exception(error_msg)

    def wait_for_vt_analysis(self, analysis_id):
        """Wait for VirusTotal analysis to complete"""
        if not analysis_id:
            print("No analysis ID provided. Skipping wait.")
            return True
            
        url = f"{self.VT_BASE_URL}/analyses/{analysis_id}"
        max_attempts = 10  # Wait up to ~1 minute (10 attempts * 6 seconds)
        
        for attempt in range(max_attempts):
            response = requests.get(url, headers=self.VT_HEADERS)
            
            if response.status_code == 200:
                json_response = response.json()
                status = json_response.get('data', {}).get('attributes', {}).get('status')
                
                if status == 'completed':
                    return True
                
                if status == 'failed':
                    raise Exception("VirusTotal analysis failed")
            
            # Wait before trying again
            time.sleep(6)
            print(f"Waiting for analysis to complete... Attempt {attempt + 1}/{max_attempts}")
        
        # Just continue even if it times out - the file might still have behavior reports
        print("Analysis wait time exceeded. Proceeding anyway.")
        return True

    def get_behavior_report(self, file_hash):
        """Get behavioral analysis data from VirusTotal using a hash"""
        url = f"{self.VT_BASE_URL}/files/{file_hash}/behaviours"
        response = requests.get(url, headers=self.VT_HEADERS)
        
        if response.status_code == 200:
            json_response = response.json()
            JSONSaver.save_api_response(json_response, 'virustotal_behavior')
            return self._process_behavior_data(json_response.get('data', []))
        else:
            print(f"[Error] Behavior data not retrieved: {response.status_code} - {response.text}")
        return None

    def get_behavior_report_from_file(self, file_path):
        """Upload a file to VirusTotal and get its behavior report"""
        print(f"Uploading file to VirusTotal: {os.path.basename(file_path)}")
        
        # Step 1: Upload the file
        upload_result = self.submit_file_to_vt(file_path)
        file_hash = upload_result['file_hash']
        analysis_id = upload_result['analysis_id']
        
        print(f"File uploaded successfully. Hash: {file_hash}")
        
        # Step 2: Wait for analysis to complete
        self.wait_for_vt_analysis(analysis_id)
        
        print("Analysis completed. Retrieving behavior report...")
        
        # Step 3: Get behavior report using the file hash
        return self.get_behavior_report(file_hash)

    def _process_behavior_data(self, behavior_data):
        """Process and structure behavior data from VirusTotal API"""
        if not behavior_data:
            return None

        processed_data = {
            'summary': {},
            'processes': [],
            'process_tree': {},  # For process hierarchy 
            'process_service_actions': [],  # New field for process and service actions
            'network_communications': [],
            'registry_keys': [],
            'files': [],
            'mutexes': [],
            'mitre_attacks': [],
            'dns_requests': [],
            'http_requests': [],
            'dropped_files': [],
            'stealth_network': {
                'ips': [],
                'domains': []
            },
            'signature_http_requests': []
        }

        for behavior in behavior_data:
            attributes = behavior.get('attributes', {})
            sandbox_name = attributes.get('sandbox_name', 'Unknown Sandbox')

            # Extract process_tree if available
            if attributes.get('processes_tree'):
                if sandbox_name not in processed_data['process_tree']:
                    processed_data['process_tree'][sandbox_name] = attributes.get('processes_tree', [])
            
            # Gather process actions
            process_actions = []
            
            # Process creations 
            if attributes.get('processes_created'):
                for proc in attributes.get('processes_created', []):
                    process_actions.append({
                        'type': 'process_created',
                        'process': proc,
                        'sandbox': sandbox_name
                    })
            
            # Process terminations
            if attributes.get('processes_terminated'):
                for proc in attributes.get('processes_terminated', []):
                    process_actions.append({
                        'type': 'process_terminated',
                        'process': proc,
                        'sandbox': sandbox_name
                    })
                
            # Service operations
            if attributes.get('services_opened'):
                for svc in attributes.get('services_opened', []):
                    process_actions.append({
                        'type': 'service_opened',
                        'service': svc,
                        'sandbox': sandbox_name
                    })
                
            if attributes.get('services_created'):
                for svc in attributes.get('services_created', []):
                    process_actions.append({
                        'type': 'service_created',
                        'service': svc,
                        'sandbox': sandbox_name
                    })
                
            if attributes.get('services_started'):
                for svc in attributes.get('services_started', []):
                    process_actions.append({
                        'type': 'service_started',
                        'service': svc,
                        'sandbox': sandbox_name
                    })
                
            if attributes.get('services_stopped'):
                for svc in attributes.get('services_stopped', []):
                    process_actions.append({
                        'type': 'service_stopped',
                        'service': svc,
                        'sandbox': sandbox_name
                    })
                
            if attributes.get('services_deleted'):
                for svc in attributes.get('services_deleted', []):
                    process_actions.append({
                        'type': 'service_deleted',
                        'service': svc,
                        'sandbox': sandbox_name
                    })
            
            # Add the process actions to our data
            processed_data['process_service_actions'].extend(process_actions)

            # The rest of the existing code...
            if sandbox_name not in processed_data['summary']:
                processed_data['summary'][sandbox_name] = {
                    'category': attributes.get('category', 'Unknown'),
                    'platform': attributes.get('platform', 'Unknown'),
                    'tags': attributes.get('tags', [])
                }

            # --- Processes ---
            for process in attributes.get('processes', []):
                processed_data['processes'].append({
                    'sandbox': sandbox_name,
                    'name': process.get('name', 'Unknown'),
                    'pid': process.get('pid', 'Unknown'),
                    'parent_pid': process.get('parent_pid', 'Unknown'),
                    'command_line': process.get('command_line', ''),
                    'path': process.get('path', ''),
                    'integrity_level': process.get('integrity_level', ''),
                    'calls': len(process.get('calls', []))
                })

            # --- Network Communications ---
            for comm in attributes.get('network_traffic', {}).get('tcp', []):
                processed_data['network_communications'].append({
                    'sandbox': sandbox_name,
                    'protocol': 'TCP',
                    'local_address': comm.get('src', ''),
                    'local_port': comm.get('sport', ''),
                    'remote_address': comm.get('dst', ''),
                    'remote_port': comm.get('dport', ''),
                })
            for comm in attributes.get('network_traffic', {}).get('udp', []):
                processed_data['network_communications'].append({
                    'sandbox': sandbox_name,
                    'protocol': 'UDP',
                    'local_address': comm.get('src', ''),
                    'local_port': comm.get('sport', ''),
                    'remote_address': comm.get('dst', ''),
                    'remote_port': comm.get('dport', ''),
                })

            # --- DNS Requests ---
            for dns in attributes.get('network_traffic', {}).get('dns', []):
                processed_data['dns_requests'].append({
                    'sandbox': sandbox_name,
                    'hostname': dns.get('hostname', ''),
                    'resolved_ips': dns.get('resolved_ips', [])
                })

            # --- HTTP Requests ---
            for http in attributes.get('network_traffic', {}).get('http', []):
                processed_data['http_requests'].append({
                    'sandbox': sandbox_name,
                    'method': http.get('method', ''),
                    'url': http.get('url', ''),
                    'user_agent': http.get('user_agent', '')
                })

            # --- Registry Keys ---
            for reg in attributes.get('registry_keys_opened', []):
                processed_data['registry_keys'].append({
                    'sandbox': sandbox_name,
                    'key': reg,
                    'operation': 'opened'
                })
            for reg in attributes.get('registry_keys_set', []):
                processed_data['registry_keys'].append({
                    'sandbox': sandbox_name,
                    'key': reg.get('key', ''),
                    'value': reg.get('value', ''),
                    'operation': 'set'
                })

            # --- Files ---
            for file in attributes.get('files_opened', []):
                processed_data['files'].append({
                    'sandbox': sandbox_name,
                    'path': file,
                    'operation': 'opened'
                })
            for file in attributes.get('files_created', []):
                processed_data['files'].append({
                    'sandbox': sandbox_name,
                    'path': file,
                    'operation': 'created'
                })
            for file in attributes.get('files_deleted', []):
                processed_data['files'].append({
                    'sandbox': sandbox_name,
                    'path': file,
                    'operation': 'deleted'
                })

            # --- Dropped Files ---
            for drop in attributes.get('dropped_files', []):
                processed_data['dropped_files'].append({
                    'sandbox': sandbox_name,
                    'file_name': drop.get('name', ''),
                    'file_type': drop.get('type_description', ''),
                    'sha256': drop.get('sha256', '')
                })

            # --- Mutexes ---
            for mutex in attributes.get('mutexes', []):
                processed_data['mutexes'].append({
                    'sandbox': sandbox_name,
                    'name': mutex
                })

            # --- MITRE ATT&CK ---
            for attack in attributes.get('mitre_attacks', []):
                processed_data['mitre_attacks'].append({
                    'sandbox': sandbox_name,
                    'id': attack.get('id', ''),
                    'name': attack.get('name', ''),
                    'tactic': attack.get('tactic', '')
                })

        # Add signature-based network data extraction
        for sandbox in behavior_data:
            attributes = sandbox.get('attributes', {})
            
            # Get signature matches
            signatures = attributes.get('signature_matches', [])
            
            for signature in signatures:
                # Process stealth network connections
                if signature.get('name') == 'stealth_network':
                    match_data = signature.get('match_data', [])
                    
                    for data_str in match_data:
                        try:
                            data = json.loads(data_str)
                            if 'ip' in data:
                                processed_data['stealth_network']['ips'].append(data['ip'])
                            elif 'domain' in data:
                                processed_data['stealth_network']['domains'].append(data['domain'])
                        except:
                            pass
                
                # Process HTTP network data from signatures
                elif signature.get('name') == 'network_http':
                    match_data = signature.get('match_data', [])
                    
                    for data_str in match_data:
                        try:
                            data = json.loads(data_str)
                            if 'url' in data:
                                processed_data['signature_http_requests'].append({
                                    'url': data['url'],
                                    'sandbox': attributes.get('sandbox_name', 'Unknown')
                                })
                        except:
                            pass
        
        return processed_data
