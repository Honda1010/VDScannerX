import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import customtkinter as ctk
from config import Config
from src.analyzers.pe_analyzer import PEAnalyzer
from src.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from src.analyzers.DynamicAnalysis import DynamicAnalyzer
from src.utils.report_generator import PDFReportGenerator
from src.utils.html_generator import HTMLReportGenerator
import webbrowser

class HashInputDialog(simpledialog.Dialog):
    def body(self, master):
        self.label = ctk.CTkLabel(master, text="Enter hash code:")
        self.label.grid(row=0, column=0, padx=5, pady=5)

        self.hash_entry = ctk.CTkEntry(master, width=400)
        self.hash_entry.grid(row=0, column=1, padx=5, pady=5)
        return self.hash_entry

    def apply(self):
        self.result = self.hash_entry.get().strip()

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("VDScannerX")
        self.root.geometry("900x600")
        self.root.resizable(True, True)  # Allow maximization

        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")

        # --- Top frame for dark mode toggle (top right) ---
        self.top_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.top_frame.pack(fill="x", pady=(10, 0), padx=10)
        self.appearance_switch = ctk.CTkSwitch(
            self.top_frame, text="🌗 Dark Mode", command=self.toggle_mode
        )
        self.appearance_switch.pack(side="right", padx=0)

        # --- Title label (centered, below toggle) ---
        self.label = ctk.CTkLabel(
            self.root,
            text="VDScannerX: Analyze. Detect. Understand",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.label.pack(pady=(10, 2))

        # --- Frame for buttons and filter bar (below the title) ---
        self.button_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.button_frame.pack(fill="x", pady=(10, 10), padx=10)

        # Upload button (add this before the analysis buttons)
        ctk.CTkButton(
            self.button_frame,
            text="⬆ Upload",
            command=self.upload_sample,
            width=90, height=32
        ).pack(side="left", padx=3)

        # Analysis buttons (smaller width)
        ctk.CTkButton(self.button_frame, text="📁 Static", 
                    command=self.do_static_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🔬 VT", 
                    command=self.do_virustotal_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🧪 Dynamic",
                    command=self.do_dynamic_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="📄 PDF", 
                    command=self.export_pdf, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🌐 Export HTML", 
                    command=self.export_html, width=100, height=32).pack(side="left", padx=3)

        # Add this with your other buttons in the button_frame
        #Virsu Total Behavior Analysis Button
        # ctk.CTkButton(
        #     self.button_frame,
        #     text="🧮 VT Behavior", 
        #     command=self.do_vt_behavior_analysis,
        #     width=100, height=32
        # ).pack(side="left", padx=3)

        # Filter bar and Apply Filter button (in button_frame)
        self.filter_var = tk.StringVar(value="All")
        ctk.CTkLabel(self.button_frame, text="String Filter:").pack(side="left", padx=5)
        self.filter_combo = ctk.CTkComboBox(
            self.button_frame,
            variable=self.filter_var,
            values=list(Config.FILTERS.keys()),
            width=100
        )
        self.filter_combo.pack(side="left", padx=3)
        ctk.CTkButton(
            self.button_frame,
            text="Apply",
            command=self.refresh_strings,
            width=70, height=32
        ).pack(side="left", padx=3)

        # Initialize analyzers 

        self.pe_analyzer = PEAnalyzer()
        self.vt_analyzer = VirusTotalAnalyzer()
        self.current_file = None

        # --- Main container and output frame ---
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=5, pady=5)
        self.setup_output_frame()

    def toggle_mode(self):
        mode = self.appearance_switch.get()
        ctk.set_appearance_mode("Dark" if mode else "Light")
        self.update_output_text_theme()

    def setup_output_frame(self):
        self.output_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=("#fff", "#23272f"),         # light, dark
            border_color=("#ccc", "#181a20"),
            border_width=2,
            corner_radius=10
        )
        self.output_panel.pack(fill="both", expand=True, padx=10, pady=10)

        self.output_text = ctk.CTkTextbox(
            self.output_panel,
            fg_color="transparent",               
            text_color=("#222", "#fff"),
            font=("Consolas", 12)
        )
        self.output_text.pack(fill="both", expand=True, padx=8, pady=8)

    def format_section_header(self, title):
        width = 80
        padding = (width - len(title) - 2) // 2
        return f"\n{'='*width}\n{' '*padding}{title}\n{'='*width}\n"

    def do_static_analysis(self):
        if not self.current_file:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", "Please upload a sample first using the Upload button.")
            return
        try:
            analysis_results = self.pe_analyzer.load_file(self.current_file)
            self.display_pe_analysis(analysis_results)
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Failed to analyze file: {str(e)}")

    def display_pe_analysis(self, results):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, self.format_section_header("Static Analysis"))
        self.output_text.insert(tk.END, f"File: {self.current_file}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("File Information"))
        for key, value in results['basic_info'].items():
            self.output_text.insert(tk.END, f"{key}: {value}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("File Hashes"))
        for hash_type, hash_value in results['hashes'].items():
            self.output_text.insert(tk.END, f"{hash_type}: {hash_value}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("PE Header Information"))
        for info in results['pe_info']:
            self.output_text.insert(tk.END, f"{info}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("PE Sections"))
        for section in results['sections']:
            self.output_text.insert(tk.END, f"Section: {section['name']}\n")
            self.output_text.insert(tk.END, f"  Virtual Address: {section['virtual_addr']}\n")
            self.output_text.insert(tk.END, f"  Virtual Size: {section['virtual_size']}\n")
            self.output_text.insert(tk.END, f"  Raw Size: {section['raw_size']}\n\n")
        
        if results.get('imports'):
            self.output_text.insert(tk.END, self.format_section_header("Imported DLLs and Functions"))
            for imp in results['imports']:
                self.output_text.insert(tk.END, f"\n📚 {imp['dll']}\n")
                for func in imp['functions']:
                    self.output_text.insert(tk.END, f"  → {func}\n")

        if results.get('exports'):
            self.output_text.insert(tk.END, self.format_section_header("Exported Functions"))
            for exp in results['exports']:
                self.output_text.insert(tk.END, f"  {exp['name']} @ {exp['address']}\n")

        self.refresh_strings()

    def refresh_strings(self):
        if not hasattr(self.pe_analyzer, 'filepath') or not self.pe_analyzer.filepath:
            return

        content = self.output_text.get(1.0, tk.END)
        start = content.find("Extracted Strings")
        if start != -1:
            self.output_text.delete(f"1.0 + {start} chars", tk.END)

        self.output_text.insert(tk.END, self.format_section_header("Extracted Strings"))
        strings = self.pe_analyzer.extract_strings(filter_name=self.filter_var.get())
        if self.filter_var.get() == "IPs":
            if strings:
                self.output_text.insert(tk.END, "  IP Addresses found:\n")
                for ip in strings[:100]:
                    self.output_text.insert(tk.END, f"    • {ip}\n")
                if len(strings) > 100:
                    self.output_text.insert(tk.END, f"\n[+] ... and {len(strings) - 100} more IPs not shown.\n")
            else:
                self.output_text.insert(tk.END, "  No IP addresses found.\n")
        else:
            for idx, s in enumerate(strings[:100], 1):
                self.output_text.insert(tk.END, f"  {idx}. {s}\n")
            if len(strings) > 100:
                self.output_text.insert(tk.END, f"\n[+] ... and {len(strings) - 100} more strings not shown.\n")

    def do_virustotal_analysis(self):
        if not self.current_file:
            #then get the hash from the user
            hash_dialog = HashInputDialog(self.root)
            file_hash = hash_dialog.result
            #if the hash is not provided, then show a message and terminate  the function
            if not file_hash:
                self.output_text.delete(1.0, "end") 
                self.output_text.insert("end", "No hash provided. Operation cancelled.")
                return
        else:
            choice = messagebox.askyesno(
                "VirusTotal Analysis",
                "Use uploaded sample's hash?\n\nYes: Use uploaded sample\nNo: Enter a hash manually"
            )
            #if the user chooses(i mean if the user clicks on yes) to use the uploaded sample, then get the hash from the pe_analyzer
            if choice:
                file_hash = self.pe_analyzer.hashes.get('SHA256')
                if not file_hash:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", "No SHA256 hash found. Please run static analysis first.")
                    return
            else:
                hash_dialog = HashInputDialog(self.root)
                file_hash = hash_dialog.result
                if not file_hash:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", "No hash provided. Operation cancelled.")
                    return

        try:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", self.format_section_header("VirusTotal Analysis"))
            self.output_text.insert("end", f"Analyzing hash: {file_hash}\nPlease wait...\n")
            self.root.update()

            result = self.vt_analyzer.get_report(file_hash)
            if result:
                self.display_vt_results(result)
            else:
                self.output_text.insert("end", "No results found on VirusTotal.\n")
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"VirusTotal analysis failed: {str(e)}")

    def display_vt_results(self, results):
        self.output_text.insert(tk.END, self.format_section_header("Basic Information"))
        self.output_text.insert(tk.END, f"SHA256: {results['hash']}\n")
        self.output_text.insert(tk.END, f"Type: {results['type']}\n")
        self.output_text.insert(tk.END, f"Size: {results['size']} bytes\n")
        self.output_text.insert(tk.END, f"First Seen: {time.strftime('%Y-%m-%d', time.localtime(results['first_seen']))}\n")
        self.output_text.insert(tk.END, f"Last Analyzed: {time.strftime('%Y-%m-%d', time.localtime(results['last_seen']))}\n")
        self.output_text.insert(tk.END, f"Detection Rate: {results['malicious_count']} / {results['total_engines']}\n")
        #analysis statistics
        self.output_text.insert(tk.END, self.format_section_header("Analysis Statistics"))
        stats = results['analysis_stats']
        self.output_text.insert(tk.END, f"Malicious: {stats.get('malicious', 0)}\n")
        self.output_text.insert(tk.END, f"Suspicious: {stats.get('suspicious', 0)}\n")
        self.output_text.insert(tk.END, f"Undetected: {stats.get('undetected', 0)}\n")
        self.output_text.insert(tk.END, f"Harmless: {stats.get('harmless', 0)}\n")
        self.output_text.insert(tk.END, f"Timeout: {stats.get('timeout', 0)}\n")
        self.output_text.insert(tk.END, f"Type Unsupported: {stats.get('type-unsupported', 0)}\n")

        if results['names']:
            self.output_text.insert(tk.END, self.format_section_header("Known Names"))
            for name in results['names'][:5]:
                self.output_text.insert(tk.END, f"  - {name}\n")

        self.output_text.insert(tk.END, self.format_section_header("Malicious Detections"))
        for engine, result in results['analysis_results'].items():
            if result.get('category') == 'malicious':
                self.output_text.insert(tk.END, f"  - {engine}: {result.get('result', 'N/A')}\n")

        # Undetected Engines
        self.output_text.insert(tk.END, self.format_section_header("Undetected Engines"))
        for engine, result in results['analysis_results'].items():
            if result.get('category') == 'undetected':
                self.output_text.insert(tk.END, f"  - {engine} (version: {result.get('engine_version', 'N/A')})\n")

    def do_dynamic_analysis(self):
        """Perform dynamic analysis by uploading a file directly"""
        # First, make sure we have a file
        if not self.current_file:
            # Prompt the user to select a file
            file_path = filedialog.askopenfilename(
                title="Select File for Dynamic Analysis",
                filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
            )
            if not file_path:
                messagebox.showinfo("Cancelled", "No file selected. Operation cancelled.")
            return
            
            # Set as current file
            self.current_file = file_path
            
        try:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", self.format_section_header("Dynamic Analysis"))
            self.output_text.insert("end", f"Analyzing file: {os.path.basename(self.current_file)}\n")
            self.output_text.insert("end", "Running comprehensive dynamic analysis...\n")
            self.output_text.insert("end", "This combines Hybrid Analysis and VirusTotal Behavior Analysis.\n")
            self.output_text.insert("end", "Please wait, this may take several minutes.\n\n")
            self.root.update()

            # First, run Hybrid Analysis
            self.output_text.insert("end", "Step 1: Submitting file to Hybrid Analysis...\n")
            self.root.update()
            hybrid_analyzer = DynamicAnalyzer()
            hybrid_result = hybrid_analyzer.analyze_file(self.current_file)
            
            # Second, run VirusTotal Behavior Analysis by uploading the file
            self.output_text.insert("end", "Step 2: Submitting file to VirusTotal and retrieving behavior data...\n")
            self.root.update()

            try:
                # Upload the file to VirusTotal and get behavior report
                vt_behavior = hybrid_analyzer.get_behavior_report_from_file(self.current_file)
            except Exception as e:
                self.output_text.insert("end", f"VirusTotal behavior analysis failed: {str(e)}\n")
                self.output_text.insert("end", "Continuing with Hybrid Analysis only.\n\n")
                vt_behavior = None
            
            # Display combined results
            self.display_combined_analysis(hybrid_result, vt_behavior)
            
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Dynamic analysis failed: {str(e)}")

    def display_combined_analysis(self, hybrid_result, vt_behavior):
        """Display combined results from Hybrid Analysis and VirusTotal Behavior Analysis in an organized way"""
        # Clear the output first
        self.output_text.delete(1.0, tk.END)
        
        # Display basic information as a summary section first
        self.output_text.insert(tk.END, self.format_section_header("Dynamic Analysis Summary"))
        
        # Extract data from hybrid_result if successful
        if hybrid_result and hybrid_result.get('success', False):
            hybrid_data = hybrid_result.get('data', {})
            
            # Basic info from Hybrid Analysis
            basic_info = hybrid_data.get('basic_info', {})
            if basic_info:
                self.output_text.insert(tk.END, "Sample Information:\n")
                self.output_text.insert(tk.END, f"File: {basic_info.get('Sample Name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Type: {basic_info.get('File Type', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Size: {basic_info.get('Size', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"SHA256: {basic_info.get('SHA256', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Verdict: {basic_info.get('Verdict', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Threat Score: {basic_info.get('Threat Score', 'Unknown')}\n\n")
        
        # Now follow the user's requested order of sections
        
        # 1. EXTRACTED FILES - from Hybrid Analysis
        if hybrid_result and hybrid_result.get('success', False):
            hybrid_data = hybrid_result.get('data', {})
            dropped_files = hybrid_data.get('dropped_files', [])
            
            if dropped_files:
                self.output_text.insert(tk.END, self.format_section_header("Extracted Files (Hybrid Analysis)"))
                for file in dropped_files:
                    self.output_text.insert(tk.END, f"Name: {file.get('name', 'Unknown')}\n")
                    if file.get('file_path'):
                        self.output_text.insert(tk.END, f"Path: {file.get('file_path')}\n")
                    if file.get('file_size'):
                        self.output_text.insert(tk.END, f"Size: {file.get('file_size')}\n")
                    if file.get('type'):
                        self.output_text.insert(tk.END, f"Type: {file.get('type')}\n")
                    if file.get('sha256'):
                        self.output_text.insert(tk.END, f"SHA256: {file.get('sha256')}\n")
                    if file.get('threat_level_readable'):
                        self.output_text.insert(tk.END, f"Threat Level: {file.get('threat_level_readable')}\n")
                    self.output_text.insert(tk.END, "\n")
        
        # Also show VirusTotal dropped files
        if vt_behavior and vt_behavior.get('dropped_files'):
            self.output_text.insert(tk.END, self.format_section_header("Extracted Files (VirusTotal)"))
            for file in vt_behavior.get('dropped_files', []):
                self.output_text.insert(tk.END, f"Name: {file.get('file_name', 'Unknown')}\n")
                if file.get('file_type'):
                    self.output_text.insert(tk.END, f"Type: {file.get('file_type')}\n")
                if file.get('sha256'):
                    self.output_text.insert(tk.END, f"SHA256: {file.get('sha256')}\n")
                self.output_text.insert(tk.END, f"Sandbox: {file.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # 2. PROCESSES - from Hybrid Analysis
        if hybrid_result and hybrid_result.get('success', False):
            hybrid_data = hybrid_result.get('data', {})
            processes = hybrid_data.get('processes', [])
            
            if processes:
                self.output_text.insert(tk.END, self.format_section_header("Processes (Hybrid Analysis)"))
                for process in processes:
                    self.output_text.insert(tk.END, f"Process: {process.get('name', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"PID: {process.get('pid', 'Unknown')}\n")
                    if process.get('parentuid'):
                        self.output_text.insert(tk.END, f"Parent UID: {process.get('parentuid')}\n")
                    if process.get('command_line'):
                        self.output_text.insert(tk.END, f"Command Line: {process.get('command_line')}\n")
                    if process.get('normalized_path'):
                        self.output_text.insert(tk.END, f"Path: {process.get('normalized_path')}\n")
                    self.output_text.insert(tk.END, "\n")
        
        # Also show VirusTotal Process and Service Actions
        if vt_behavior and vt_behavior.get('process_service_actions'):
            self.output_text.insert(tk.END, self.format_section_header("Process and Service Actions (VirusTotal)"))
            
            # Group actions by type for better organization
            action_groups = {
                'process_created': [],
                'process_terminated': [],
                'service_opened': [],
                'service_created': [],
                'service_started': [],
                'service_stopped': [],
                'service_deleted': []
            }
            
            for action in vt_behavior.get('process_service_actions', []):
                action_type = action.get('type', 'unknown')
                if action_type in action_groups:
                    action_groups[action_type].append(action)
            
            # Display Process Creation
            if action_groups['process_created']:
                self.output_text.insert(tk.END, "Processes Created:\n")
                for action in action_groups['process_created']:
                    self.output_text.insert(tk.END, f"  • {action.get('process', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"    Sandbox: {action.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
                
            # Display Process Termination
            if action_groups['process_terminated']:
                self.output_text.insert(tk.END, "Processes Terminated:\n")
                for action in action_groups['process_terminated']:
                    self.output_text.insert(tk.END, f"  • {action.get('process', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"    Sandbox: {action.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
                
            # Display Service Operations
            if any(len(action_groups[k]) > 0 for k in ['service_opened', 'service_created', 'service_started', 'service_stopped', 'service_deleted']):
                self.output_text.insert(tk.END, "Service Operations:\n")
                
                if action_groups['service_created']:
                    self.output_text.insert(tk.END, "  Services Created:\n")
                    for action in action_groups['service_created']:
                        self.output_text.insert(tk.END, f"    • {action.get('service', 'Unknown')}\n")
                    
                if action_groups['service_started']:
                    self.output_text.insert(tk.END, "  Services Started:\n")
                    for action in action_groups['service_started']:
                        self.output_text.insert(tk.END, f"    • {action.get('service', 'Unknown')}\n")
                        
                if action_groups['service_stopped']:
                    self.output_text.insert(tk.END, "  Services Stopped:\n")
                    for action in action_groups['service_stopped']:
                        self.output_text.insert(tk.END, f"    • {action.get('service', 'Unknown')}\n")
                        
                if action_groups['service_deleted']:
                    self.output_text.insert(tk.END, "  Services Deleted:\n")
                    for action in action_groups['service_deleted']:
                        self.output_text.insert(tk.END, f"    • {action.get('service', 'Unknown')}\n")
                
                self.output_text.insert(tk.END, "\n")
        
        # Also show VirusTotal processes
        if vt_behavior and vt_behavior.get('processes'):
            self.output_text.insert(tk.END, self.format_section_header("Processes (VirusTotal)"))
            for process in vt_behavior.get('processes', []):
                self.output_text.insert(tk.END, f"Name: {process.get('name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"PID: {process.get('pid', 'Unknown')}\n")
                if process.get('parent_pid'):
                    self.output_text.insert(tk.END, f"Parent PID: {process.get('parent_pid')}\n")
                if process.get('command_line'):
                    self.output_text.insert(tk.END, f"Command Line: {process.get('command_line')}\n")
                if process.get('path'):
                    self.output_text.insert(tk.END, f"Path: {process.get('path')}\n")
                if process.get('integrity_level'):
                    self.output_text.insert(tk.END, f"Integrity Level: {process.get('integrity_level')}\n")
                self.output_text.insert(tk.END, f"API Calls: {process.get('calls', 0)}\n")
                self.output_text.insert(tk.END, f"Sandbox: {process.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display Process Tree for VirusTotal
        if vt_behavior and vt_behavior['process_tree']:
            self.output_text.insert(tk.END, self.format_section_header("Process Tree (VirusTotal)"))
            
            # For each sandbox, display its process tree
            for sandbox, process_tree in vt_behavior['process_tree'].items():
                if process_tree:
                    self.output_text.insert(tk.END, f"Sandbox: {sandbox}\n\n")
                    for process in process_tree:
                        pid = process.get('process_id', 'Unknown')
                        name = process.get('name', 'Unknown')
                        self.output_text.insert(tk.END, f"• {name} (PID: {pid})\n")
                    self.output_text.insert(tk.END, "\n")
        
        # 3. MITRE ATT&CK - from Hybrid Analysis
        if hybrid_result and hybrid_result.get('success', False):
            hybrid_data = hybrid_result.get('data', {})
            mitre_attacks = hybrid_data.get('mitre_attacks', [])
            
            if mitre_attacks:
                self.output_text.insert(tk.END, self.format_section_header("MITRE ATT&CK Techniques (Hybrid Analysis)"))
                for attack in mitre_attacks:
                    self.output_text.insert(tk.END, f"Tactic: {attack.get('tactic', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"Technique: {attack.get('technique', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"ATT&CK ID: {attack.get('attck_id', 'Unknown')}\n")
                    if attack.get('attck_id_wiki'):
                        self.output_text.insert(tk.END, f"Wiki: {attack.get('attck_id_wiki')}\n")
                    if attack.get('description'):
                        self.output_text.insert(tk.END, f"Description: {attack.get('description')}\n")
                    self.output_text.insert(tk.END, "\n")
        
        # Also show VirusTotal MITRE ATT&CK
        if vt_behavior and vt_behavior.get('mitre_attacks'):
            self.output_text.insert(tk.END, self.format_section_header("MITRE ATT&CK Techniques (VirusTotal)"))
            
            # Group by technique ID to avoid duplicates
            techniques = {}
            for technique in vt_behavior.get('mitre_attacks', []):
                technique_id = technique.get('id', 'Unknown')
                if technique_id not in techniques:
                    techniques[technique_id] = technique
                    techniques[technique_id]['sandboxes'] = [technique.get('sandbox')]
                else:
                    if technique.get('sandbox') not in techniques[technique_id]['sandboxes']:
                        techniques[technique_id]['sandboxes'].append(technique.get('sandbox'))
            
            for technique_id, technique in techniques.items():
                self.output_text.insert(tk.END, f"ID: {technique_id}\n")
                self.output_text.insert(tk.END, f"Name: {technique.get('name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Tactic: {technique.get('tactic', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Observed in: {', '.join(technique.get('sandboxes', []))}\n")
                self.output_text.insert(tk.END, "\n")
        
        # 4. NETWORK INFORMATION - from VirusTotal (more comprehensive)
        if vt_behavior:
            network_activity = False
            
            if (vt_behavior.get('network_communications') or 
                vt_behavior.get('dns_requests') or 
                vt_behavior.get('http_requests') or
                (vt_behavior.get('stealth_network') and (vt_behavior['stealth_network']['ips'] or vt_behavior['stealth_network']['domains'])) or
                vt_behavior.get('signature_http_requests')):
                
                self.output_text.insert(tk.END, self.format_section_header("Network Communication"))
                network_activity = True
                
                # TCP/UDP communications
                if vt_behavior.get('network_communications'):
                    self.output_text.insert(tk.END, "Network Connections:\n")
                    for comm in vt_behavior.get('network_communications', []):
                        protocol = comm.get('protocol', 'Unknown')
                        remote_addr = comm.get('remote_address', 'Unknown')
                        remote_port = comm.get('remote_port', 'Unknown')
                        sandbox = comm.get('sandbox', 'Unknown')
                        
                        self.output_text.insert(tk.END, f"  • {protocol} {remote_addr}:{remote_port}\n")
                        self.output_text.insert(tk.END, f"    Sandbox: {sandbox}\n")
                        
                        if comm.get('local_address') and comm.get('local_port'):
                            local_addr = comm.get('local_address')
                            local_port = comm.get('local_port')
                            self.output_text.insert(tk.END, f"    Local: {local_addr}:{local_port}\n")
                    
                    self.output_text.insert(tk.END, "\n")
                
                # Stealth network activity
                if vt_behavior.get('stealth_network') and (vt_behavior['stealth_network']['ips'] or vt_behavior['stealth_network']['domains']):
                    self.output_text.insert(tk.END, "Stealth Network Activity:\n")
                    
                    # Display IPs
                    if vt_behavior['stealth_network']['ips']:
                        self.output_text.insert(tk.END, "  IP Connections:\n")
                        for ip in vt_behavior['stealth_network']['ips']:
                            self.output_text.insert(tk.END, f"    • {ip}\n")
                        self.output_text.insert(tk.END, "\n")
                    
                    # Display domains
                    if vt_behavior['stealth_network']['domains']:
                        self.output_text.insert(tk.END, "  Domain Connections:\n")
                        for domain in vt_behavior['stealth_network']['domains']:
                            self.output_text.insert(tk.END, f"    • {domain}\n")
                        self.output_text.insert(tk.END, "\n")
                
                # DNS requests
                if vt_behavior.get('dns_requests'):
                    self.output_text.insert(tk.END, "DNS Requests:\n")
                    for dns in vt_behavior.get('dns_requests', []):
                        hostname = dns.get('hostname', 'Unknown')
                        resolved_ips = ', '.join(dns.get('resolved_ips', []) or ['None'])
                        sandbox = dns.get('sandbox', 'Unknown')
                        
                        self.output_text.insert(tk.END, f"  • {hostname} → {resolved_ips}\n")
                        self.output_text.insert(tk.END, f"    Sandbox: {sandbox}\n")
                    
                    self.output_text.insert(tk.END, "\n")
                
                # HTTP requests
                if vt_behavior.get('http_requests'):
                    self.output_text.insert(tk.END, "HTTP Requests:\n")
                    for http in vt_behavior.get('http_requests', []):
                        method = http.get('method', 'GET')
                        url = http.get('url', 'Unknown')
                        sandbox = http.get('sandbox', 'Unknown')
                        
                        self.output_text.insert(tk.END, f"  • {method} {url}\n")
                        self.output_text.insert(tk.END, f"    Sandbox: {sandbox}\n")
                        
                        if http.get('user_agent'):
                            self.output_text.insert(tk.END, f"    User-Agent: {http.get('user_agent')}\n")
                    
                    self.output_text.insert(tk.END, "\n")
                
                # Signature-based HTTP requests
                if vt_behavior.get('signature_http_requests'):
                    self.output_text.insert(tk.END, "Additional HTTP Activity:\n")
                    for http in vt_behavior.get('signature_http_requests', []):
                        url = http.get('url', 'Unknown')
                        sandbox = http.get('sandbox', 'Unknown')
                        
                        self.output_text.insert(tk.END, f"  • GET {url}\n")
                        self.output_text.insert(tk.END, f"    Sandbox: {sandbox}\n")
                    
                    self.output_text.insert(tk.END, "\n")
            
            # Show extracted URLs from Hybrid Analysis alongside network activity
            if (hybrid_result and hybrid_result.get('success', False) and 
                hybrid_result.get('data', {}).get('extracted_urls')):
                
                if not network_activity:
                    self.output_text.insert(tk.END, self.format_section_header("Network Activity"))
                
                urls = hybrid_result.get('data', {}).get('extracted_urls', [])
                if urls:
                    self.output_text.insert(tk.END, "Extracted URLs (Hybrid Analysis):\n")
                    for url in urls:
                        self.output_text.insert(tk.END, f"  • {url}\n")
                    self.output_text.insert(tk.END, "\n")
        
        # 5. SIGNATURES - from Hybrid Analysis
        if hybrid_result and hybrid_result.get('success', False):
            hybrid_data = hybrid_result.get('data', {})
            signatures = hybrid_data.get('signatures', [])
            
            if signatures:
             self.output_text.insert(tk.END, self.format_section_header("Detected Signatures (Hybrid Analysis)"))
            
            # Group signatures by category
            signatures_by_category = {}
            for sig in signatures:
                category = sig.get('category', 'Uncategorized')
                if category not in signatures_by_category:
                    signatures_by_category[category] = []
                signatures_by_category[category].append(sig)
            
            # Display signatures by category
            for category, sigs in signatures_by_category.items():
                    self.output_text.insert(tk.END, f"\n--- {category} ---\n")
                    self.output_text.insert(tk.END, "\n")
                    for sig in sigs:
                        name = sig.get('name', 'Unknown')
                        description = sig.get('description', '')
                        threat_level = sig.get('threat_level_human', 'Unknown')
                        self.output_text.insert(tk.END, f"• {name} [{threat_level}]\n")
                        if description:
                            self.output_text.insert(tk.END, f"  {description}\n")
                        self.output_text.insert(tk.END, "\n")


        
        
        # Add file operations section from VirusTotal
        if vt_behavior and vt_behavior.get('files'):
            self.output_text.insert(tk.END, self.format_section_header("File Operations (VirusTotal)"))
            
            # Group by operation
            operations = {'created': [], 'opened': [], 'deleted': []}
            for file in vt_behavior.get('files', []):
                op = file.get('operation', 'unknown')
                if op in operations:
                    operations[op].append(file)
            
            # Display created files
            if operations['created']:
                self.output_text.insert(tk.END, "Files Created:\n")
                for file in operations['created']:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display opened files (limit to 20)
            if operations['opened']:
                self.output_text.insert(tk.END, "Files Opened (limited to first 20):\n")
                for file in operations['opened'][:20]:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                if len(operations['opened']) > 20:
                    self.output_text.insert(tk.END, f"  • ... and {len(operations['opened']) - 20} more\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display deleted files
            if operations['deleted']:
                self.output_text.insert(tk.END, "Files Deleted:\n")
                for file in operations['deleted']:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Add registry operations section from VirusTotal
        if vt_behavior and vt_behavior.get('registry_keys'):
            self.output_text.insert(tk.END, self.format_section_header("Registry Operations (VirusTotal)"))
            
            # Group by operation
            operations = {'opened': [], 'set': []}
            for reg in vt_behavior.get('registry_keys', []):
                op = reg.get('operation', 'unknown')
                if op in operations:
                    operations[op].append(reg)
            
            # Display modified keys (set)
            if operations['set']:
                self.output_text.insert(tk.END, "Registry Keys Modified:\n")
                for reg in operations['set']:
                    key = reg.get('key', 'Unknown')
                    value = reg.get('value', '')
                    if value:
                        self.output_text.insert(tk.END, f"  • {key} = {value}\n")
                    else:
                        self.output_text.insert(tk.END, f"  • {key}\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display opened keys (limit to 20)
            if operations['opened']:
                self.output_text.insert(tk.END, "Registry Keys Accessed (limited to first 20):\n")
                for reg in operations['opened'][:20]:
                    self.output_text.insert(tk.END, f"  • {reg.get('key', 'Unknown')}\n")
                if len(operations['opened']) > 20:
                    self.output_text.insert(tk.END, f"  • ... and {len(operations['opened']) - 20} more\n")
                self.output_text.insert(tk.END, "\n")

    def do_vt_behavior_analysis(self):
        """Perform VirusTotal behavior analysis with file upload option"""
        # First, determine what to analyze (file or hash)
        if not self.current_file:
            # No file is loaded, ask user to select one or enter a hash
            # choice = messagebox.askyesno(
            #     "VirusTotal Behavior Analysis",
            #     "No file is currently loaded.\n\nYes: Select a file to upload\nNo: Enter a hash manually"
            # )
            choice = True
            if choice:
                # User wants to select a file
                file_path = filedialog.askopenfilename(
                    title="Select File for VirusTotal Analysis",
                    filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
                )
                if not file_path:
                    messagebox.showinfo("Cancelled", "Operation cancelled.")
                    return
                    
                # Use this file 
                self.current_file = file_path
                self.output_text.delete(1.0, "end")
                self.output_text.insert("end", f"File selected: {os.path.basename(file_path)}\n")
            else:
                # User wants to enter a hash
                hash_dialog = HashInputDialog(self.root)
                file_hash = hash_dialog.result
                if not file_hash:
                    messagebox.showinfo("Cancelled", "No hash provided. Operation cancelled.")
                    return
                    
                # Analyze this hash directly
                try:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", self.format_section_header("VirusTotal Behavior Analysis"))
                    self.output_text.insert("end", f"Analyzing hash: {file_hash}\nPlease wait...\n")
                    self.root.update()
                    
                    analyzer = DynamicAnalyzer()
                    behavior_data = analyzer.get_behavior_report(file_hash)
                    
                    if behavior_data:
                        self.display_vt_behavior(behavior_data)
                    else:
                        self.output_text.insert("end", "No behavior data found on VirusTotal for this hash.")
                    return
                except Exception as e:
                    messagebox.showerror("Error", f"VirusTotal behavior analysis failed: {str(e)}")
                    return
        
        # At this point we have a file (either previously loaded or just selected)
        # Ask if user wants to upload file or use hash
        choice = messagebox.askyesno(
            "VirusTotal Behavior Analysis",
            "How would you like to analyze this file?\n\nYes: Upload file for fresh analysis\nNo: Use file hash (faster if already analyzed)"
        )
        
        try:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", self.format_section_header("VirusTotal Behavior Analysis"))
            
            analyzer = DynamicAnalyzer()
            
            if choice:
                # Upload the file for analysis
                self.output_text.insert("end", f"Uploading file: {os.path.basename(self.current_file)}\n")
                self.output_text.insert("end", "This may take several minutes...\n")
                self.root.update()
                
                # First make sure we have a complete static analysis
                if not hasattr(self.pe_analyzer, 'hashes') or not self.pe_analyzer.hashes:
                    self.pe_analyzer.load_file(self.current_file)
                
                # Use the upload and wait approach
                behavior_data = analyzer.get_behavior_report_from_file(self.current_file)
            else:
                # Use file hash
                if not hasattr(self.pe_analyzer, 'hashes') or not self.pe_analyzer.hashes:
                    self.output_text.insert("end", "Running static analysis to get file hash...\n")
                    self.root.update()
                    self.pe_analyzer.load_file(self.current_file)
                
                file_hash = self.pe_analyzer.hashes.get('SHA256')
                if not file_hash:
                    messagebox.showerror("Error", "Failed to obtain file hash")
                    return
                    
                self.output_text.insert("end", f"Using hash: {file_hash}\n")
                self.output_text.insert("end", "Retrieving behavior data...\n")
                self.root.update()
                
                behavior_data = analyzer.get_behavior_report(file_hash)
            
            if behavior_data:
                self.display_vt_behavior(behavior_data)
            else:
                self.output_text.insert("end", "\nNo behavior data found on VirusTotal for this sample.")
            
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"VirusTotal behavior analysis failed: {str(e)}")

    def display_vt_behavior(self, behavior_data):
        """Display VirusTotal behavior analysis results"""
        # Display summary information
        self.output_text.insert(tk.END, self.format_section_header("Behavior Summary"))
        
        if not behavior_data['summary']:
            self.output_text.insert(tk.END, "No sandbox analysis data available.\n")
        else:
            for sandbox, info in behavior_data['summary'].items():
                self.output_text.insert(tk.END, f"Sandbox: {sandbox}\n")
                self.output_text.insert(tk.END, f"Category: {info.get('category', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Platform: {info.get('platform', 'Unknown')}\n")
                
                if info.get('tags'):
                    self.output_text.insert(tk.END, f"Tags: {', '.join(info.get('tags', []))}\n")
                
                self.output_text.insert(tk.END, "\n")
        
        # Display MITRE ATT&CK techniques
        if behavior_data['mitre_attacks']:
            self.output_text.insert(tk.END, self.format_section_header("MITRE ATT&CK Techniques"))
            
            # Group by technique ID to avoid duplicates
            techniques = {}
            for technique in behavior_data['mitre_attacks']:
                technique_id = technique.get('id', 'Unknown')
                if technique_id not in techniques:
                    techniques[technique_id] = technique
                    techniques[technique_id]['sandboxes'] = [technique.get('sandbox')]
                else:
                    if technique.get('sandbox') not in techniques[technique_id]['sandboxes']:
                        techniques[technique_id]['sandboxes'].append(technique.get('sandbox'))
            
            for technique_id, technique in techniques.items():
                self.output_text.insert(tk.END, f"ID: {technique_id}\n")
                self.output_text.insert(tk.END, f"Name: {technique.get('name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Tactic: {technique.get('tactic', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Observed in: {', '.join(technique.get('sandboxes', []))}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display processes
        if behavior_data['processes']:
            self.output_text.insert(tk.END, self.format_section_header("Processes"))
            
            for process in behavior_data['processes']:
                self.output_text.insert(tk.END, f"Name: {process.get('name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"PID: {process.get('pid', 'Unknown')}\n")
                if process.get('parent_pid'):
                    self.output_text.insert(tk.END, f"Parent PID: {process.get('parent_pid')}\n")
                if process.get('command_line'):
                    self.output_text.insert(tk.END, f"Command Line: {process.get('command_line')}\n")
                if process.get('path'):
                    self.output_text.insert(tk.END, f"Path: {process.get('path')}\n")
                if process.get('integrity_level'):
                    self.output_text.insert(tk.END, f"Integrity Level: {process.get('integrity_level')}\n")
                self.output_text.insert(tk.END, f"API Calls: {process.get('calls', 0)}\n")
                self.output_text.insert(tk.END, f"Sandbox: {process.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display network communications
        if behavior_data['network_communications'] or behavior_data['dns_requests'] or behavior_data['http_requests']:
            self.output_text.insert(tk.END, self.format_section_header("Network Activity"))
            
            # TCP/UDP communications
            if behavior_data['network_communications']:
                self.output_text.insert(tk.END, "Network Connections:\n")
                for comm in behavior_data['network_communications']:
                    protocol = comm.get('protocol', 'Unknown')
                    remote_addr = comm.get('remote_address', 'Unknown')
                    remote_port = comm.get('remote_port', 'Unknown')
                    
                    self.output_text.insert(tk.END, f"  • {protocol} {remote_addr}:{remote_port}\n")
                    
                    if comm.get('local_address') and comm.get('local_port'):
                        local_addr = comm.get('local_address')
                        local_port = comm.get('local_port')
                        self.output_text.insert(tk.END, f"    Local: {local_addr}:{local_port}\n")
                
                self.output_text.insert(tk.END, "\n")
            
            # DNS requests
            if behavior_data['dns_requests']:
                self.output_text.insert(tk.END, "DNS Requests:\n")
                for dns in behavior_data['dns_requests']:
                    hostname = dns.get('hostname', 'Unknown')
                    resolved_ips = ', '.join(dns.get('resolved_ips', []) or ['None'])
                    
                    self.output_text.insert(tk.END, f"  • {hostname} → {resolved_ips}\n")
                
                self.output_text.insert(tk.END, "\n")
            
            # HTTP requests
            if behavior_data['http_requests']:
                self.output_text.insert(tk.END, "HTTP Requests:\n")
                for http in behavior_data['http_requests']:
                    method = http.get('method', 'GET')
                    url = http.get('url', 'Unknown')
                    
                    self.output_text.insert(tk.END, f"  • {method} {url}\n")
                    
                    if http.get('user_agent'):
                        self.output_text.insert(tk.END, f"    User-Agent: {http.get('user_agent')}\n")
                
                self.output_text.insert(tk.END, "\n")
        
        # Display file operations
        if behavior_data['files']:
            self.output_text.insert(tk.END, self.format_section_header("File Operations"))
            
            # Group by operation
            operations = {'created': [], 'opened': [], 'deleted': []}
            for file in behavior_data['files']:
                op = file.get('operation', 'unknown')
                if op in operations:
                    operations[op].append(file)
            
            # Display created files
            if operations['created']:
                self.output_text.insert(tk.END, "Files Created:\n")
                for file in operations['created']:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display opened files (limit to 20)
            if operations['opened']:
                self.output_text.insert(tk.END, "Files Opened (limited to first 20):\n")
                for file in operations['opened'][:20]:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                if len(operations['opened']) > 20:
                    self.output_text.insert(tk.END, f"  • ... and {len(operations['opened']) - 20} more\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display deleted files
            if operations['deleted']:
                self.output_text.insert(tk.END, "Files Deleted:\n")
                for file in operations['deleted']:
                    self.output_text.insert(tk.END, f"  • {file.get('path', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display dropped files
        if behavior_data['dropped_files']:
            self.output_text.insert(tk.END, self.format_section_header("Dropped Files"))
            
            for file in behavior_data['dropped_files']:
                self.output_text.insert(tk.END, f"Name: {file.get('file_name', 'Unknown')}\n")
                if file.get('file_type'):
                    self.output_text.insert(tk.END, f"Type: {file.get('file_type')}\n")
                if file.get('sha256'):
                    self.output_text.insert(tk.END, f"SHA256: {file.get('sha256')}\n")
                self.output_text.insert(tk.END, f"Sandbox: {file.get('sandbox', 'Unknown')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display registry operations
        if behavior_data['registry_keys']:
            self.output_text.insert(tk.END, self.format_section_header("Registry Operations"))
            
            # Group by operation
            operations = {'opened': [], 'set': []}
            for reg in behavior_data['registry_keys']:
                op = reg.get('operation', 'unknown')
                if op in operations:
                    operations[op].append(reg)
            
            # Display modified keys (set)
            if operations['set']:
                self.output_text.insert(tk.END, "Registry Keys Modified:\n")
                for reg in operations['set']:
                    key = reg.get('key', 'Unknown')
                    value = reg.get('value', '')
                    if value:
                        self.output_text.insert(tk.END, f"  • {key} = {value}\n")
                    else:
                        self.output_text.insert(tk.END, f"  • {key}\n")
                self.output_text.insert(tk.END, "\n")
            
            # Display opened keys (limit to 20)
            if operations['opened']:
                self.output_text.insert(tk.END, "Registry Keys Accessed (limited to first 20):\n")
                for reg in operations['opened'][:20]:
                    self.output_text.insert(tk.END, f"  • {reg.get('key', 'Unknown')}\n")
                if len(operations['opened']) > 20:
                    self.output_text.insert(tk.END, f"  • ... and {len(operations['opened']) - 20} more\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display mutexes
        if behavior_data['mutexes']:
            self.output_text.insert(tk.END, self.format_section_header("Mutexes"))
            
            # Get unique mutex names
            unique_mutexes = set()
            for mutex in behavior_data['mutexes']:
                unique_mutexes.add(mutex.get('name', 'Unknown'))
            
            for mutex in sorted(unique_mutexes):
                self.output_text.insert(tk.END, f"  • {mutex}\n")

    def export_pdf(self):
        try:
            os.makedirs(Config.OUTPUT_FOLDER, exist_ok=True)
            current_content = self.output_text.get(1.0, tk.END)
            if not current_content.strip():
                messagebox.showwarning("Warning", "No content to export.")
                return

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_report_{timestamp}.pdf"
            filepath = os.path.join(Config.OUTPUT_FOLDER, filename)
            report = PDFReportGenerator(filepath)
            report.generate_from_text(current_content)
            
            messagebox.showinfo("Success", f"Report saved as {filename} in output_pdf directory")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")

    def export_html(self):
        try:
            current_content = self.output_text.get(1.0, tk.END)
            if not current_content.strip():
                messagebox.showwarning("Warning", "No content to export.")
                return

            html_generator = HTMLReportGenerator()
            output_file = html_generator.generate_from_text(current_content)
            
            webbrowser.open('file://' + os.path.realpath(output_file))
            
            messagebox.showinfo("Success", f"HTML report saved and opened in browser:\n{os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")

    def update_output_text_theme(self):
        # Detect current mode
        mode = ctk.get_appearance_mode()
        if mode == "Dark":
            self.output_text.configure(bg="#23272f", fg="#f5f5f5", insertbackground="#f5f5f5")
        else:
            self.output_text.configure(bg="#ffffff", fg="#222222", insertbackground="#222222")

    def upload_sample(self):
        file_path = filedialog.askopenfilename(
            title="Select Sample File",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
        )
        if file_path:
            self.current_file = file_path
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Sample uploaded:\n{file_path}\n\nReady for analysis.")
        else:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", "No sample selected.")